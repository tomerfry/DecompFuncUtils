<#
.SYNOPSIS
    Route a Claude Code session to a specific Ghidra MCP server so multiple
    sessions can run in parallel against different binaries without colliding.

.DESCRIPTION
    Each running Ghidra instance (with the DecompFuncUtils MCP server started)
    advertises itself in ~/.ghidra-mcp/server-<pid>.json. This launcher discovers
    the live servers, picks one (by loaded binary name, by port, or interactively),
    exports GHIDRA_MCP_URL for it, and launches `claude`.

    The project's .mcp.json reads ${GHIDRA_MCP_URL:-...}, so the chosen server is
    the only one this Claude session can talk to.

.PARAMETER Binary
    Substring of the loaded program/binary name to match (case-insensitive).
    Routes to the single Ghidra instance holding a matching target.

.PARAMETER Port
    Connect to the server on this exact port (skips discovery matching).

.PARAMETER List
    Print the discovered live servers and exit (no launch).

.EXAMPLE
    ./tools/ghidra-claude.ps1 -Binary libfoo.so
    Launch Claude bound to the Ghidra instance that has libfoo.so open.

.EXAMPLE
    ./tools/ghidra-claude.ps1 -List
    Show every live Ghidra MCP server and its loaded binary.

.NOTES
    Any extra arguments after the named parameters are forwarded to `claude`.
#>
[CmdletBinding()]
param(
    [string]$Binary,
    [int]$Port,
    [switch]$List,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ClaudeArgs
)

$ErrorActionPreference = 'Stop'
$portDir = Join-Path $HOME '.ghidra-mcp'

function Get-LiveServers {
    if (-not (Test-Path $portDir)) { return @() }
    $servers = @()
    foreach ($file in Get-ChildItem -Path $portDir -Filter 'server-*.json' -ErrorAction SilentlyContinue) {
        try {
            $info = Get-Content -Raw -LiteralPath $file.FullName | ConvertFrom-Json
        } catch {
            continue
        }
        # Prune entries whose owning Ghidra process is gone.
        $alive = $false
        if ($info.pid) {
            $alive = $null -ne (Get-Process -Id $info.pid -ErrorAction SilentlyContinue)
        }
        if (-not $alive) {
            Remove-Item -LiteralPath $file.FullName -ErrorAction SilentlyContinue
            continue
        }
        # Confirm the HTTP server actually answers (and pick up live session count).
        $sessions = $null
        try {
            $disc = Invoke-RestMethod -Uri "http://127.0.0.1:$($info.port)/discovery" -TimeoutSec 2
            $sessions = $disc.activeSessions
        } catch {
            continue  # process alive but server not listening yet / wrong port
        }
        $servers += [pscustomobject]@{
            Port           = [int]$info.port
            Pid            = [int]$info.pid
            Project        = $info.project
            Program        = $info.program
            Programs       = $info.programs
            ActiveSessions = $sessions
            Url            = $info.url
        }
    }
    return $servers | Sort-Object Port
}

function Format-Programs($s) {
    if ($s.Programs) { return ($s.Programs -join ', ') }
    if ($s.Program)  { return $s.Program }
    return '(no program loaded)'
}

$servers = Get-LiveServers

if ($List) {
    if (-not $servers) {
        Write-Host 'No live Ghidra MCP servers found in ~/.ghidra-mcp/.'
        Write-Host 'Start one in Ghidra: Tools -> MCP Server -> Start.'
        return
    }
    Write-Host ''
    Write-Host 'Live Ghidra MCP servers:'
    $i = 1
    foreach ($s in $servers) {
        $busy = if ($s.ActiveSessions -gt 0) { "  [in use: $($s.ActiveSessions) session(s)]" } else { '' }
        Write-Host ("  [{0}] port {1}  pid {2}  project '{3}'  programs: {4}{5}" -f `
            $i, $s.Port, $s.Pid, $s.Project, (Format-Programs $s), $busy)
        $i++
    }
    Write-Host ''
    return
}

if (-not $servers) {
    Write-Error 'No live Ghidra MCP servers found. In Ghidra: Tools -> MCP Server -> Start, then retry.'
    return
}

# ---- Select a server ----
$chosen = $null

if ($Port) {
    $chosen = $servers | Where-Object { $_.Port -eq $Port } | Select-Object -First 1
    if (-not $chosen) { Write-Error "No live MCP server on port $Port."; return }
}
elseif ($Binary) {
    $matched = $servers | Where-Object {
        ($_.Program -and $_.Program -like "*$Binary*") -or
        ($_.Programs -and ($_.Programs | Where-Object { $_ -like "*$Binary*" }))
    }
    if (-not $matched) {
        Write-Error "No live Ghidra instance has a binary matching '*$Binary*'. Use -List to see what's open."
        return
    }
    if (@($matched).Count -gt 1) {
        Write-Error "Multiple instances match '*$Binary*'. Narrow the name or use -Port. (-List to see them.)"
        return
    }
    $chosen = @($matched)[0]
}
elseif (@($servers).Count -eq 1) {
    $chosen = $servers[0]
}
else {
    # Interactive pick. Prefer flagging idle servers, but let the user choose.
    Write-Host ''
    Write-Host 'Multiple Ghidra MCP servers are running. Choose one:'
    for ($i = 0; $i -lt $servers.Count; $i++) {
        $s = $servers[$i]
        $busy = if ($s.ActiveSessions -gt 0) { "  [in use: $($s.ActiveSessions)]" } else { '  [idle]' }
        Write-Host ("  [{0}] port {1}  '{2}'  {3}{4}" -f ($i + 1), $s.Port, $s.Project, (Format-Programs $s), $busy)
    }
    $sel = Read-Host 'Enter number'
    $idx = 0
    if (-not [int]::TryParse($sel, [ref]$idx) -or $idx -lt 1 -or $idx -gt $servers.Count) {
        Write-Error 'Invalid selection.'; return
    }
    $chosen = $servers[$idx - 1]
}

if ($chosen.ActiveSessions -gt 0) {
    Write-Warning ("Port {0} already has {1} active session(s). Launching anyway will share that Ghidra instance." -f `
        $chosen.Port, $chosen.ActiveSessions)
}

$env:GHIDRA_MCP_URL = "http://127.0.0.1:$($chosen.Port)/sse"
Write-Host ("Routing this Claude session to Ghidra on port {0} (programs: {1})" -f `
    $chosen.Port, (Format-Programs $chosen)) -ForegroundColor Green
Write-Host ("GHIDRA_MCP_URL = {0}" -f $env:GHIDRA_MCP_URL) -ForegroundColor DarkGray

# Hand off to Claude Code in this same shell so it inherits GHIDRA_MCP_URL.
& claude @ClaudeArgs
