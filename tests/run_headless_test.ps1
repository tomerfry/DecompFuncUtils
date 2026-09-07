<#
.SYNOPSIS
  Build the extension, install the fresh build, and run the headless taint/emulator
  regression test against tests/test_vuln.o. Exits 0 on PASS, 1 on FAIL.

.NOTES
  Requires a Ghidra install (GHIDRA_INSTALL_DIR env var, or the -GhidraInstall param).
  The extension is loaded by Ghidra as an installed module, so this script installs the
  freshly built zip into the per-user Extensions dir for the matching Ghidra version and
  refuses to run with a copy under <install>/Ghidra/Extensions (two copies of the same module name
  make Ghidra abort with "Multiple modules collided"). The Ghidra project is created in
  $env:TEMP so it is never scanned as a module.
#>
[CmdletBinding()]
param(
    [string]$GhidraInstall = $(if ($env:GHIDRA_INSTALL_DIR) { $env:GHIDRA_INSTALL_DIR } else { "C:\Users\User\Ghidra" }),
    [switch]$SkipBuild,
    # Post-script to run: TaintHeadlessTest.java (default, taint/emulator regression)
    # or McpTransportHeadlessTest.java (MCP transport handshake test).
    [string]$Script = 'TaintHeadlessTest.java'
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$hl   = Join-Path $GhidraInstall "support\analyzeHeadless.bat"
if (-not (Test-Path $hl)) { Write-Error "analyzeHeadless not found at $hl (set GHIDRA_INSTALL_DIR)"; exit 2 }

# 1) Build the extension (compiles src + packages dist zip).
if (-not $SkipBuild) {
    Write-Host "==> Building extension..." -ForegroundColor Cyan
    Push-Location $repo
    try {
        $env:GHIDRA_INSTALL_DIR = $GhidraInstall
        & gradle --offline buildExtension -q
        if ($LASTEXITCODE -ne 0) { throw "Extension build failed" }
    }
    finally { Pop-Location }
}

# 2) Locate freshest dist zip. The module name follows the checkout directory, so a
#    worktree builds e.g. DecompFuncUtils.improve.zip — match either.
$zip = Get-ChildItem (Join-Path $repo "dist\*DecompFuncUtils*.zip") | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $zip) { Write-Error "No built extension zip in dist/"; exit 2 }

# 3) Resolve an isolated settings dir for this run.
#    Installing into %APPDATA%\ghidra fails while a GUI Ghidra holds the jar open
#    ("being used by another process"), so the test gets its own settings tree via
#    XDG_CONFIG_HOME (launch.properties precedence rule 2). A running Ghidra — and
#    its live MCP server — is left completely untouched.
$ver = (Get-Content (Join-Path $GhidraInstall "Ghidra\application.properties") |
        Select-String '^application.version=(.+)$').Matches.Groups[1].Value.Trim()
$runId = [guid]::NewGuid().ToString("N")
$settingsRoot = Join-Path $env:TEMP "dfu_ghidra_settings_$runId"
$extDir = Join-Path $settingsRoot "ghidra\ghidra_${ver}_DEV\Extensions"
New-Item -ItemType Directory -Force $extDir | Out-Null

# 4) Install fresh build as the single DecompFuncUtils module.
#    A copy under <install>\Ghidra\Extensions would collide with this one
#    ("Multiple modules collided"), so require a clean installation.
$module = [System.IO.Path]::GetFileNameWithoutExtension($zip.Name) -replace '^ghidra_.+?_\d{8}_', ''
if (Test-Path -LiteralPath (Join-Path $GhidraInstall "Ghidra\Extensions\$module")) {
    throw "An extension exists in the Ghidra installation. Use a clean Ghidra installation for isolated tests."
}
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::ExtractToDirectory($zip.FullName, $extDir)
Write-Host "==> Installed $($zip.Name) -> $extDir" -ForegroundColor Cyan

# 5) Run the test headless (project in TEMP so the repo module isn't double-scanned).
$proj = Join-Path $env:TEMP "dfu_ghidra_proj_$runId"
New-Item -ItemType Directory -Force $proj | Out-Null
$bin = Join-Path $repo "tests\test_vuln.o"
$sp  = Join-Path $repo "tests\scripts"
$log = Join-Path $repo "tests\_last_run.log"

Write-Host "==> Running headless test..." -ForegroundColor Cyan
# analyzeHeadless writes benign warnings (e.g. sun.misc.Unsafe) to stderr; under
# ErrorActionPreference=Stop PowerShell would turn those into a terminating error
# and abort before we read the result. Relax it just for this native call.
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$prevXdg = $env:XDG_CONFIG_HOME
$env:XDG_CONFIG_HOME = $settingsRoot
try {
    & $hl $proj T -import $bin -scriptPath $sp -postScript $Script -deleteProject *>&1 |
        Out-File -FilePath $log -Encoding utf8
}
finally {
    if ($null -eq $prevXdg) { Remove-Item Env:\XDG_CONFIG_HOME -ErrorAction SilentlyContinue }
    else { $env:XDG_CONFIG_HOME = $prevXdg }
}
$ErrorActionPreference = $prevEAP

# 6) Report.
$lines = Get-Content $log | Where-Object { $_ -match 'CHECK |HEADLESS_TEST_SUMMARY|HEADLESS_TEST_RESULT|INFO with_call' }
$lines | ForEach-Object { ($_ -replace '^INFO\s+\S+\.java>\s*', '') -replace '\s*\(GhidraScript\)\s*$', '' } |
    ForEach-Object {
        if ($_ -match ': FAIL')      { Write-Host $_ -ForegroundColor Red }
        elseif ($_ -match ': PASS')  { Write-Host $_ -ForegroundColor Green }
        else                         { Write-Host $_ }
    }

if (Select-String -Path $log -Pattern 'HEADLESS_TEST_RESULT PASS' -Quiet) {
    Write-Host "==> RESULT: PASS" -ForegroundColor Green; exit 0
} else {
    Write-Host "==> RESULT: FAIL (see $log)" -ForegroundColor Red; exit 1
}
