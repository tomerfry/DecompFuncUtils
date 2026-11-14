<#
.SYNOPSIS
  Build the extension, install the fresh build into an isolated settings tree, and run the
  headless regression test for ghidra_angr_emulate. Exits 0 on PASS, 1 on FAIL, 2 when it
  cannot run.

.NOTES
  Imports tests/angr/libangrdemo.so with auto-analysis (the tool calls functions by name, so
  they have to exist). Rebuild the fixture with tests/angr/build.ps1 (needs clang + lld); the
  built ELF is committed so the test does not need a compiler.

  Needs a Python with angr. By default the test uses whatever the extension itself would find
  (the environment recorded by tools/setup-angr.ps1); pass -Python to test against another one.

  Like the other runners, this installs into a temporary XDG_CONFIG_HOME so a running GUI
  Ghidra keeps its own jar and is left untouched.
#>
[CmdletBinding()]
param(
    [string]$GhidraInstall = $(if ($env:GHIDRA_INSTALL_DIR) { $env:GHIDRA_INSTALL_DIR } else { "C:\Users\User\Ghidra" }),
    [switch]$SkipBuild,
    [string]$GradleExe = "gradle",
    # Interpreter to run angr under; exported to the test as DFU_ANGR_PYTHON.
    [string]$Python = "",
    # Where the throwaway settings tree, project and exported image go.
    [string]$WorkRoot = $env:TEMP
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$hl   = Join-Path $GhidraInstall "support\analyzeHeadless.bat"
if (-not (Test-Path $hl)) { Write-Error "analyzeHeadless not found at $hl (set GHIDRA_INSTALL_DIR)"; exit 2 }

$fixture = Join-Path $repo "tests\angr\libangrdemo.so"
if (-not (Test-Path -LiteralPath $fixture)) { Write-Error "Missing fixture $fixture - run tests\angr\build.ps1"; exit 2 }

# An interpreter that can import angr, found the same way the extension finds one.
if (-not $Python) {
    $pointer = Join-Path $HOME ".decompfuncutils\angr-python"
    $venv = Join-Path $HOME ".decompfuncutils\angr-venv\Scripts\python.exe"
    if ($env:DFU_ANGR_PYTHON) { $Python = $env:DFU_ANGR_PYTHON }
    elseif (Test-Path -LiteralPath $pointer) { $Python = (Get-Content -LiteralPath $pointer -Raw).Trim() }
    elseif (Test-Path -LiteralPath $venv) { $Python = $venv }
}
if (-not $Python -or -not (Test-Path -LiteralPath $Python)) {
    Write-Error "No Python with angr is set up. Run tools\setup-angr.ps1 first, or pass -Python."; exit 2
}

if (-not $SkipBuild) {
    Write-Host "==> Building extension..." -ForegroundColor Cyan
    Push-Location $repo
    try {
        $env:GHIDRA_INSTALL_DIR = $GhidraInstall
        & $GradleExe buildExtension -q --console=plain
        if ($LASTEXITCODE -ne 0) { throw "Extension build failed" }
    }
    finally { Pop-Location }
}

$zip = Get-ChildItem (Join-Path $repo "dist\*DecompFuncUtils*.zip") | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $zip) { Write-Error "No built extension zip in dist/"; exit 2 }

# Isolated settings dir; the path has to match what this Ghidra computes (see
# run_resolve_externals_test.ps1 for why each part is read from the install).
$props = Get-Content (Join-Path $GhidraInstall "Ghidra\application.properties")
$ver = ($props | Select-String '^application.version=(.+)$').Matches.Groups[1].Value.Trim()
$releaseName = ($props | Select-String '^application.release.name=(.+)$').Matches.Groups[1].Value.Trim()
$layoutMatch = $props | Select-String '^application.layout.version=(.+)$'
$layout = if ($layoutMatch) { [int]$layoutMatch.Matches.Groups[1].Value.Trim() } else { 2 }
$settingsParent = if ($layout -ge 3) { "$env:USERNAME-ghidra" } else { "ghidra" }

$runId = [guid]::NewGuid().ToString("N")
$settingsRoot = Join-Path $WorkRoot "dfu_ghidra_settings_$runId"
$extDir = Join-Path $settingsRoot "$settingsParent\ghidra_${ver}_${releaseName}\Extensions"
New-Item -ItemType Directory -Force $extDir | Out-Null

$module = [System.IO.Path]::GetFileNameWithoutExtension($zip.Name) -replace '^ghidra_.+?_\d{8}_', ''
if (Test-Path -LiteralPath (Join-Path $GhidraInstall "Ghidra\Extensions\$module")) {
    throw "An extension exists in the Ghidra installation. Use a clean Ghidra installation for isolated tests."
}
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::ExtractToDirectory($zip.FullName, $extDir)
Write-Host "==> Installed $($zip.Name) -> $extDir" -ForegroundColor Cyan
Write-Host "==> angr interpreter: $Python" -ForegroundColor Cyan

$proj = Join-Path $WorkRoot "dfu_ghidra_proj_$runId"
$imageTmp = Join-Path $WorkRoot "dfu_angr_tmp_$runId"
New-Item -ItemType Directory -Force $proj, $imageTmp | Out-Null
$sp  = Join-Path $repo "tests\scripts"
$log = Join-Path $repo "tests\_last_AngrEmulateHeadlessTest_run.log"

Write-Host "==> Running headless test..." -ForegroundColor Cyan
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$prevXdg = $env:XDG_CONFIG_HOME
$prevPy = $env:DFU_ANGR_PYTHON
$prevTmp = $env:DFU_ANGR_TMP
$env:XDG_CONFIG_HOME = $settingsRoot
$env:DFU_ANGR_PYTHON = $Python
$env:DFU_ANGR_TMP = $imageTmp
$hlArgs = @($proj, 'T', '-import', $fixture, '-scriptPath', $sp,
    '-postScript', 'AngrEmulateHeadlessTest.java', '-deleteProject')
try {
    & $hl @hlArgs *>&1 | Out-File -FilePath $log -Encoding utf8
}
finally {
    foreach ($pair in @(@('XDG_CONFIG_HOME', $prevXdg), @('DFU_ANGR_PYTHON', $prevPy), @('DFU_ANGR_TMP', $prevTmp))) {
        if ($null -eq $pair[1]) { Remove-Item "Env:\$($pair[0])" -ErrorAction SilentlyContinue }
        else { Set-Item "Env:\$($pair[0])" $pair[1] }
    }
    Remove-Item -Recurse -Force $settingsRoot, $proj, $imageTmp -ErrorAction SilentlyContinue
}
$ErrorActionPreference = $prevEAP

$lines = Get-Content $log | Where-Object { $_ -match 'CHECK |HEADLESS_TEST_SUMMARY|HEADLESS_TEST_RESULT' }
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
