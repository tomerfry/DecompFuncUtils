<#
.SYNOPSIS
    Route a Claude Code or Codex session to a specific Ghidra MCP server so
    multiple sessions can run in parallel against different binaries without
    colliding.

.DESCRIPTION
    Each running Ghidra instance (with the DecompFuncUtils MCP server started)
    advertises itself in ~/.ghidra-mcp/server-<pid>.json. This launcher discovers
    the live servers, picks one (by loaded binary name, by port, or interactively),
    and launches the agent bound to it.

    Claude Code: GHIDRA_MCP_URL is exported with the chosen server's legacy SSE
    URL. The project's .mcp.json reads ${GHIDRA_MCP_URL:-...}, so that server is
    the only one the session can talk to.

    Codex: launched with -c mcp_servers.ghidra.url set to the chosen server's
    Streamable HTTP (/mcp) URL, overriding .codex/config.toml. Codex has no legacy
    SSE transport, and TOML cannot read environment variables, so the override is
    passed on the command line.

.PARAMETER Client
    Which agent to launch: claude (default) or codex.

.PARAMETER Binary
    Substring of the loaded program/binary name to match (case-insensitive).
    Routes to the single Ghidra instance holding a matching target.

.PARAMETER Port
    Connect to the server on this exact port (skips discovery matching).
    Defaults to the port in $env:GHIDRA_MCP_URL when that is set.

.PARAMETER List
    Print the discovered live servers and exit (no launch).

.EXAMPLE
    ./tools/ghidra-claude.ps1 -Binary libfoo.so
    Launch Claude bound to the Ghidra instance that has libfoo.so open.

.EXAMPLE
    ./tools/ghidra-claude.ps1 -Client codex -Binary libfoo.so
    Same, but launch Codex against that instance's /mcp endpoint.

.EXAMPLE
    ./tools/ghidra-claude.ps1 -List
    Show every live Ghidra MCP server and its loaded binary.

.NOTES
    Any extra arguments after the named parameters are forwarded to the agent.
    Use tools/mcp-handshake-probe.ps1 to diagnose a server that is reachable
    but fails to hand shake.
#>
[CmdletBinding()]
param(
    [ValidateSet('claude', 'codex')]
    [string]$Client = 'claude',
    [string]$Binary,
    [int]$Port,
    [switch]$List,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$AgentArgs
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

# An already-set GHIDRA_MCP_URL is an explicit routing choice; honour it so the
# same variable selects the instance for both agents.
if (-not $Port -and -not $Binary -and $env:GHIDRA_MCP_URL -match ':(\d+)') {
    $Port = [int]$Matches[1]
    Write-Host "Using port $Port from GHIDRA_MCP_URL" -ForegroundColor DarkGray
}

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

Write-Host ("Routing this {0} session to Ghidra on port {1} (programs: {2})" -f `
    $Client, $chosen.Port, (Format-Programs $chosen)) -ForegroundColor Green

if ($Client -eq 'codex') {
    # Codex speaks Streamable HTTP only; -c overrides .codex/config.toml's url.
    $mcpUrl = "http://127.0.0.1:$($chosen.Port)/mcp"
    Write-Host ("mcp_servers.ghidra.url = {0}" -f $mcpUrl) -ForegroundColor DarkGray
    & codex -c "mcp_servers.ghidra.url=`"$mcpUrl`"" @AgentArgs
}
else {
    # Claude Code reads ${GHIDRA_MCP_URL:-...} from .mcp.json; hand off in this
    # same shell so the child process inherits it.
    $env:GHIDRA_MCP_URL = "http://127.0.0.1:$($chosen.Port)/sse"
    Write-Host ("GHIDRA_MCP_URL = {0}" -f $env:GHIDRA_MCP_URL) -ForegroundColor DarkGray
    & claude @AgentArgs
}
