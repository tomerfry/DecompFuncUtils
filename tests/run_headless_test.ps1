<#
.SYNOPSIS
  Build the extension, install the fresh build, and run the headless taint/emulator
  regression test against tests/test_vuln.o. Exits 0 on PASS, 1 on FAIL.

.NOTES
  Requires a Ghidra install (GHIDRA_INSTALL_DIR env var, or the -GhidraInstall param).
  The extension is loaded by Ghidra as an installed module, so this script installs the
  freshly built zip into the per-user Extensions dir for the matching Ghidra version and
  removes any copy under <install>/Ghidra/Extensions (two copies of the same module name
  make Ghidra abort with "Multiple modules collided"). The Ghidra project is created in
  $env:TEMP so it is never scanned as a module.
#>
[CmdletBinding()]
param(
    [string]$GhidraInstall = $(if ($env:GHIDRA_INSTALL_DIR) { $env:GHIDRA_INSTALL_DIR } else { "C:\Users\User\Ghidra" }),
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$hl   = Join-Path $GhidraInstall "support\analyzeHeadless.bat"
if (-not (Test-Path $hl)) { Write-Error "analyzeHeadless not found at $hl (set GHIDRA_INSTALL_DIR)"; exit 2 }

# 1) Build the extension (compiles src + packages dist zip).
if (-not $SkipBuild) {
    Write-Host "==> Building extension..." -ForegroundColor Cyan
    Push-Location $repo
    try { $env:GHIDRA_INSTALL_DIR = $GhidraInstall; & gradle --offline buildExtension -q }
    finally { Pop-Location }
}

# 2) Locate freshest dist zip.
$zip = Get-ChildItem (Join-Path $repo "dist\*DecompFuncUtils.zip") | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $zip) { Write-Error "No built extension zip in dist/"; exit 2 }

# 3) Resolve the per-user Extensions dir for this Ghidra version.
$ver = (Get-Content (Join-Path $GhidraInstall "Ghidra\application.properties") |
        Select-String '^application.version=(.+)$').Matches.Groups[1].Value.Trim()
$userGhidra = Join-Path $env:APPDATA "ghidra"
$extDir = Get-ChildItem $userGhidra -Directory -Filter "ghidra_${ver}_*" -ErrorAction SilentlyContinue |
          ForEach-Object { Join-Path $_.FullName "Extensions" } | Where-Object { Test-Path (Split-Path $_ -Parent) } |
          Select-Object -First 1
if (-not $extDir) { $extDir = Join-Path $userGhidra "ghidra_${ver}_DEV\Extensions" }
New-Item -ItemType Directory -Force $extDir | Out-Null

# 4) Install fresh build as the single DecompFuncUtils module.
Remove-Item -Recurse -Force (Join-Path $GhidraInstall "Ghidra\Extensions\DecompFuncUtils") -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force (Join-Path $extDir "DecompFuncUtils") -ErrorAction SilentlyContinue
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::ExtractToDirectory($zip.FullName, $extDir)
Write-Host "==> Installed $($zip.Name) -> $extDir" -ForegroundColor Cyan

# 5) Run the test headless (project in TEMP so the repo module isn't double-scanned).
$proj = Join-Path $env:TEMP "dfu_ghidra_proj"
if (Test-Path $proj) { Remove-Item -Recurse -Force $proj }
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
& $hl $proj T -import $bin -scriptPath $sp -postScript TaintHeadlessTest.java -deleteProject *>&1 |
    Out-File -FilePath $log -Encoding utf8
$ErrorActionPreference = $prevEAP

# 6) Report.
$lines = Get-Content $log | Where-Object { $_ -match 'CHECK |HEADLESS_TEST_SUMMARY|HEADLESS_TEST_RESULT|INFO with_call' }
$lines | ForEach-Object { ($_ -replace '^INFO\s+TaintHeadlessTest\.java>\s*', '') -replace '\s*\(GhidraScript\)\s*$', '' } |
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
