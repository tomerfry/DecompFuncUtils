<#
.SYNOPSIS
    Verify an MCP handshake against a live Ghidra MCP server, on either transport.

.DESCRIPTION
    Runs the full client handshake and reports PASS/FAIL per step:

      Streamable HTTP (/mcp)      - what Codex speaks
        1. POST initialize      -> 200 + Mcp-Session-Id header
        2. POST notifications/initialized -> 202
        3. POST tools/list      -> 200 with ghidra_* tools
        4. DELETE session       -> 204

      Legacy HTTP+SSE (/sse + /message) - what Claude Code's "sse" client speaks
        1. GET /sse             -> stays open, first event advertises /message?sessionId=...
        2. POST initialize      -> 202, response arrives on the SSE stream
        3. POST notifications/initialized -> 202
        4. POST tools/list      -> 202, response arrives on the SSE stream

    The SSE stream is expected to stay open - that is a healthy server, not a
    timeout. The probe reads it incrementally in the background and never treats
    "still connected" as a failure. The sessionId is always taken from the live
    endpoint event; nothing transient is hardcoded.

.PARAMETER Port
    Port of the Ghidra MCP server (13100-13149). Defaults to $env:GHIDRA_MCP_URL's
    port, else the single live server found in ~/.ghidra-mcp, else 13100.

.PARAMETER Url
    Full base URL (e.g. http://127.0.0.1:13101). Overrides -Port.

.PARAMETER Transport
    Which transport to probe: http (Streamable HTTP), sse (legacy), or both (default).

.EXAMPLE
    ./tools/mcp-handshake-probe.ps1 -Port 13101

.EXAMPLE
    ./tools/mcp-handshake-probe.ps1 -Transport sse

.NOTES
    Exit code 0 = every probed step passed, 1 = at least one failed,
    2 = could not determine a server to probe.
#>
[CmdletBinding()]
param(
    [int]$Port,
    [string]$Url,
    [ValidateSet('http', 'sse', 'both')]
    [string]$Transport = 'both',
    [int]$TimeoutSec = 15
)

$ErrorActionPreference = 'Stop'
$script:passed = 0
$script:failed = 0

function Step($name, $ok, $detail) {
    if ($ok) {
        $script:passed++
        Write-Host ("  [PASS] {0}" -f $name) -ForegroundColor Green
    } else {
        $script:failed++
        Write-Host ("  [FAIL] {0} - {1}" -f $name, $detail) -ForegroundColor Red
    }
}

# ---- Resolve the target server ----

function Resolve-BaseUrl {
    if ($Url)  { return $Url.TrimEnd('/') -replace '/(sse|mcp)$', '' }
    if ($Port) { return "http://127.0.0.1:$Port" }
    if ($env:GHIDRA_MCP_URL -and $env:GHIDRA_MCP_URL -match ':(\d+)') {
        return "http://127.0.0.1:$($Matches[1])"
    }
    $dir = Join-Path $HOME '.ghidra-mcp'
    if (Test-Path $dir) {
        $live = @()
        foreach ($f in Get-ChildItem $dir -Filter 'server-*.json' -ErrorAction SilentlyContinue) {
            try { $info = Get-Content -Raw -LiteralPath $f.FullName | ConvertFrom-Json } catch { continue }
            if ($info.pid -and (Get-Process -Id $info.pid -ErrorAction SilentlyContinue)) { $live += $info }
        }
        if (@($live).Count -eq 1) { return "http://127.0.0.1:$($live[0].port)" }
        if (@($live).Count -gt 1) {
            # Several entries can share a pid: one MCP server per Ghidra tool window.
            Write-Host 'Multiple live Ghidra MCP windows; pass -Port to choose one:' -ForegroundColor Yellow
            $live | ForEach-Object {
                Write-Host ("  port {0}  {1}  pid {2}  project '{3}'" -f `
                    $_.port, $(if ($_.window) { $_.window } else { '?' }), $_.pid, $_.project)
            }
            return $null
        }
    }
    return 'http://127.0.0.1:13100'
}

$base = Resolve-BaseUrl
if (-not $base) { exit 2 }

Write-Host ''
Write-Host "MCP handshake probe -> $base" -ForegroundColor Cyan

# Reachability first, so a dead port is not reported as a protocol failure.
try {
    $disc = Invoke-RestMethod -Uri "$base/discovery" -TimeoutSec 5
    $win = if ($disc.window) { " window '$($disc.window)'," } else { '' }
    Write-Host ("  server up: port {0},{1} {2} SSE session(s)" -f $disc.port, $win, $disc.activeSessions) -ForegroundColor DarkGray
} catch {
    Write-Host "  [FAIL] server not reachable at $base/discovery - is the MCP server started in Ghidra?" -ForegroundColor Red
    Write-Host '         (Ghidra: Tools -> MCP Server -> Start)' -ForegroundColor DarkGray
    exit 1
}

# ---- Streamable HTTP (/mcp) ----

function Test-StreamableHttp {
    Write-Host ''
    Write-Host 'Streamable HTTP  (/mcp - Codex)' -ForegroundColor Cyan

    $initBody = @{
        jsonrpc = '2.0'; id = 1; method = 'initialize'
        params  = @{
            protocolVersion = '2025-06-18'
            capabilities    = @{}
            clientInfo      = @{ name = 'mcp-handshake-probe'; version = '1.0' }
        }
    } | ConvertTo-Json -Depth 6 -Compress

    try {
        $resp = Invoke-WebRequest -Uri "$base/mcp" -Method Post -Body $initBody `
            -ContentType 'application/json' `
            -Headers @{ Accept = 'application/json, text/event-stream' } `
            -TimeoutSec $TimeoutSec -UseBasicParsing
    } catch {
        $code = $null
        if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
        if ($code -eq 404 -or $code -eq 405) {
            Step 'initialize' $false ("/mcp returned $code - this Ghidra is running an older build with no Streamable HTTP endpoint. Install the current extension and restart Ghidra (legacy /sse still works meanwhile).")
        } else {
            Step 'initialize' $false "POST /mcp failed: $($_.Exception.Message)"
        }
        return
    }

    Step 'initialize (200)' ($resp.StatusCode -eq 200) "got HTTP $($resp.StatusCode)"
    $sid = $resp.Headers['Mcp-Session-Id']
    if ($sid -is [array]) { $sid = $sid[0] }
    Step 'Mcp-Session-Id issued' ([bool]$sid) 'response carried no Mcp-Session-Id header'

    $init = $resp.Content | ConvertFrom-Json
    Step 'initialize result' ($null -ne $init.result -and $null -ne $init.result.serverInfo) `
        "unexpected body: $($resp.Content)"
    if ($init.result) {
        Write-Host ("         server: {0} {1}, protocol {2}" -f `
            $init.result.serverInfo.name, $init.result.serverInfo.version, $init.result.protocolVersion) -ForegroundColor DarkGray
    }
    # Integer ids must come back as integers; "id":1.0 breaks strict clients.
    Step 'JSON-RPC id fidelity' ($resp.Content -notmatch '"id"\s*:\s*\d+\.\d') `
        'server echoed a non-integer id (e.g. 1.0)'

    $hdrs = @{ Accept = 'application/json, text/event-stream' }
    if ($sid) { $hdrs['Mcp-Session-Id'] = $sid }

    try {
        $note = Invoke-WebRequest -Uri "$base/mcp" -Method Post `
            -Body '{"jsonrpc":"2.0","method":"notifications/initialized"}' `
            -ContentType 'application/json' -Headers $hdrs -TimeoutSec $TimeoutSec -UseBasicParsing
        Step 'notifications/initialized (202)' ($note.StatusCode -eq 202) "got HTTP $($note.StatusCode)"
    } catch {
        Step 'notifications/initialized (202)' $false $_.Exception.Message
    }

    try {
        $tl = Invoke-WebRequest -Uri "$base/mcp" -Method Post `
            -Body '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' `
            -ContentType 'application/json' -Headers $hdrs -TimeoutSec $TimeoutSec -UseBasicParsing
        $tools = ($tl.Content | ConvertFrom-Json).result.tools
        $ghidraTools = @($tools | Where-Object { $_.name -like 'ghidra_*' })
        Step 'tools/list' ($ghidraTools.Count -gt 0) "returned $($ghidraTools.Count) ghidra_* tools"
        if ($ghidraTools.Count -gt 0) {
            Write-Host ("         {0} tools, e.g. {1}" -f $ghidraTools.Count,
                (($ghidraTools | Select-Object -First 3 | ForEach-Object { $_.name }) -join ', ')) -ForegroundColor DarkGray
        }
    } catch {
        Step 'tools/list' $false $_.Exception.Message
    }

    if ($sid) {
        try {
            $del = Invoke-WebRequest -Uri "$base/mcp" -Method Delete `
                -Headers @{ 'Mcp-Session-Id' = $sid } -TimeoutSec $TimeoutSec -UseBasicParsing
            Step 'session teardown (204)' ($del.StatusCode -eq 204) "got HTTP $($del.StatusCode)"
        } catch {
            Step 'session teardown (204)' $false $_.Exception.Message
        }
    }
}

# ---- Legacy HTTP+SSE (/sse + /message) ----

function Test-LegacySse {
    Write-Host ''
    Write-Host 'Legacy HTTP+SSE  (/sse + /message - Claude Code)' -ForegroundColor Cyan

    $reader = $null
    $stream = $null
    $resp   = $null
    try {
        # HttpWebRequest returns once the headers are in, leaving the chunked body
        # streaming - exactly what an SSE client needs. (Invoke-WebRequest would
        # instead block until the body ends, which for /sse is never.)
        $req = [System.Net.HttpWebRequest]::Create("$base/sse")
        $req.Method = 'GET'
        $req.Accept = 'text/event-stream'
        $req.Timeout = $TimeoutSec * 1000
        $req.ReadWriteTimeout = $TimeoutSec * 1000
        try {
            $resp = $req.GetResponse()
        } catch {
            Step 'GET /sse opens' $false "no response headers: $($_.Exception.Message)"
            return
        }
        Step 'GET /sse opens' `
            ([int]$resp.StatusCode -eq 200 -and $resp.ContentType -match 'text/event-stream') `
            "HTTP $([int]$resp.StatusCode), Content-Type $($resp.ContentType)"

        $stream = $resp.GetResponseStream()
        $stream.ReadTimeout = $TimeoutSec * 1000
        $reader = New-Object System.IO.StreamReader($stream)

        # Reads one SSE frame at a time. Responses to a POST are pushed onto this
        # stream, so reading *after* each POST picks them up without any threading.
        # A stalled read raises IOException, which we report as a failed step
        # rather than letting it hang - but a stream that simply stays open
        # between events is the healthy case.
        function Read-Event($reader, $wantEvent, $wantId) {
            $event = $null; $data = ''
            while ($true) {
                try { $line = $reader.ReadLine() } catch { return $null }
                if ($null -eq $line) { return $null }
                if ($line -eq '') {
                    if ($event -eq $wantEvent -and $data) {
                        if ($null -eq $wantId) { return $data }
                        try { $msg = $data | ConvertFrom-Json } catch { $msg = $null }
                        if ($msg -and $msg.id -eq $wantId) { return $data }
                    }
                    $event = $null; $data = ''
                } elseif ($line.StartsWith('event: ')) {
                    $event = $line.Substring(7)
                } elseif ($line.StartsWith('data: ')) {
                    if ($data) { $data += "`n" }
                    $data += $line.Substring(6)
                }
                # ": keepalive" comment lines fall through and are ignored
            }
        }

        $endpoint = Read-Event $reader 'endpoint' $null
        Step 'endpoint event received' `
            ($endpoint -and $endpoint -match '/message\?sessionId=') `
            'no endpoint event on the stream'
        if (-not $endpoint) { return }
        Write-Host ("         message endpoint: {0}" -f $endpoint) -ForegroundColor DarkGray

        $initBody = @{
            jsonrpc = '2.0'; id = 1; method = 'initialize'
            params  = @{
                protocolVersion = '2024-11-05'
                capabilities    = @{}
                clientInfo      = @{ name = 'mcp-handshake-probe'; version = '1.0' }
            }
        } | ConvertTo-Json -Depth 6 -Compress

        $init = Invoke-WebRequest -Uri $endpoint -Method Post -Body $initBody `
            -ContentType 'application/json' -TimeoutSec $TimeoutSec -UseBasicParsing
        Step 'initialize accepted (202)' ($init.StatusCode -eq 202) "got HTTP $($init.StatusCode)"

        $initResp = Read-Event $reader 'message' 1
        Step 'initialize response over SSE' ([bool]$initResp) 'no initialize response on the stream'
        if ($initResp) {
            $parsed = $initResp | ConvertFrom-Json
            Write-Host ("         server: {0} {1}, protocol {2}" -f `
                $parsed.result.serverInfo.name, $parsed.result.serverInfo.version,
                $parsed.result.protocolVersion) -ForegroundColor DarkGray
        }

        $note = Invoke-WebRequest -Uri $endpoint -Method Post `
            -Body '{"jsonrpc":"2.0","method":"notifications/initialized"}' `
            -ContentType 'application/json' -TimeoutSec $TimeoutSec -UseBasicParsing
        Step 'notifications/initialized (202)' ($note.StatusCode -eq 202) "got HTTP $($note.StatusCode)"

        $tl = Invoke-WebRequest -Uri $endpoint -Method Post `
            -Body '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' `
            -ContentType 'application/json' -TimeoutSec $TimeoutSec -UseBasicParsing
        Step 'tools/list accepted (202)' ($tl.StatusCode -eq 202) "got HTTP $($tl.StatusCode)"

        $toolsResp = Read-Event $reader 'message' 2
        if ($toolsResp) {
            $ghidraTools = @(($toolsResp | ConvertFrom-Json).result.tools | Where-Object { $_.name -like 'ghidra_*' })
            Step 'tools/list response over SSE' ($ghidraTools.Count -gt 0) 'no ghidra_* tools returned'
            Write-Host ("         {0} tools, e.g. {1}" -f $ghidraTools.Count,
                (($ghidraTools | Select-Object -First 3 | ForEach-Object { $_.name }) -join ', ')) -ForegroundColor DarkGray
        } else {
            Step 'tools/list response over SSE' $false 'no tools/list response on the stream'
        }

        # The stream is still open here - that is the expected steady state.
        Write-Host '         SSE stream still open (expected - not a timeout)' -ForegroundColor DarkGray
    }
    finally {
        if ($reader) { $reader.Dispose() }
        if ($stream) { $stream.Dispose() }
        if ($resp)   { $resp.Close() }
    }
}

if ($Transport -eq 'http' -or $Transport -eq 'both') { Test-StreamableHttp }
if ($Transport -eq 'sse'  -or $Transport -eq 'both') { Test-LegacySse }

Write-Host ''
if ($script:failed -eq 0) {
    Write-Host ("RESULT: PASS ({0} checks)" -f $script:passed) -ForegroundColor Green
    exit 0
} else {
    Write-Host ("RESULT: FAIL ({0} passed, {1} failed)" -f $script:passed, $script:failed) -ForegroundColor Red
    exit 1
}
