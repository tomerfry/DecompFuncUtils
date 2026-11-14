<#
.SYNOPSIS
  Open the Refined Decompiler for real - in a Ghidra tool window, not a headless run - and check
  it. Exits 0 on PASS, 1 on FAIL, 2 when it cannot run.

.DESCRIPTION
  What the headless test cannot reach lives in a window: the plugin loading into a code browser,
  the window following the cursor, the code changing as the configuration is edited, a click on
  a refined line moving the Listing, an edit to the program refreshing the view. This runner
  starts decompfuncutils.refine.ui.RefinedDecompilerPreview through Ghidra's own launcher on
  tests/refine/librefinedemo.so, prints its CHECK lines, and leaves pictures of the window in
  tests/_refined_gui_*.png.

  The window is placed off-screen and never takes focus, so it does not get in the way; it is
  painted into the pictures rather than looked at.

  Like the other runners this installs the build into a temporary settings tree, so a running
  Ghidra keeps its own copy and is left alone.
#>
[CmdletBinding()]
param(
    [string]$GhidraInstall = $(if ($env:GHIDRA_INSTALL_DIR) { $env:GHIDRA_INSTALL_DIR } else { "C:\Users\User\Ghidra" }),
    [switch]$SkipBuild,
    [string]$GradleExe = "gradle",
    [string]$WorkRoot = $env:TEMP
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$launch = Join-Path $GhidraInstall "support\launch.bat"
if (-not (Test-Path $launch)) { Write-Error "launch.bat not found at $launch (set GHIDRA_INSTALL_DIR)"; exit 2 }
$fixture = Join-Path $repo "tests\refine\librefinedemo.so"
if (-not (Test-Path -LiteralPath $fixture)) { Write-Error "Missing fixture $fixture - run tests\refine\build.ps1"; exit 2 }

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

$props = Get-Content (Join-Path $GhidraInstall "Ghidra\application.properties")
$ver = ($props | Select-String '^application.version=(.+)$').Matches.Groups[1].Value.Trim()
$releaseName = ($props | Select-String '^application.release.name=(.+)$').Matches.Groups[1].Value.Trim()
$layoutMatch = $props | Select-String '^application.layout.version=(.+)$'
$layout = if ($layoutMatch) { [int]$layoutMatch.Matches.Groups[1].Value.Trim() } else { 2 }
$settingsParent = if ($layout -ge 3) { "$env:USERNAME-ghidra" } else { "ghidra" }
Add-Type -AssemblyName System.IO.Compression.FileSystem

$runId = [guid]::NewGuid().ToString("N")
$settingsRoot = Join-Path $WorkRoot "dfu_ghidra_settings_$runId"
$extDir = Join-Path $settingsRoot "$settingsParent\ghidra_${ver}_${releaseName}\Extensions"
$zip = Get-ChildItem (Join-Path $repo "dist\*DecompFuncUtils*.zip") | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $zip) { Write-Error "No built extension zip in dist/"; exit 2 }
New-Item -ItemType Directory -Force $extDir | Out-Null
[System.IO.Compression.ZipFile]::ExtractToDirectory($zip.FullName, $extDir)
Write-Host "==> Installed $($zip.Name)" -ForegroundColor Cyan

$log = Join-Path $repo "tests\_last_RefinedDecompilerGui_run.log"
$prevXdg = $env:XDG_CONFIG_HOME
$prevEAP = $ErrorActionPreference
try {
    $env:XDG_CONFIG_HOME = $settingsRoot
    Write-Host "==> Opening the window..." -ForegroundColor Cyan
    $ErrorActionPreference = 'Continue'
    # The VM-argument slot must not be empty (PowerShell drops an empty argument and launch.bat
    # would take the class name for it) and must not contain '=', which cmd splits arguments
    # on. A property nobody reads fits both.
    $all = @('fg', 'jdk', 'RefinedDecompilerPreview', '2G', '-Ddfu.refine.preview',
        'decompfuncutils.refine.ui.RefinedDecompilerPreview', (Join-Path $repo "tests"), $fixture)
    # launch.bat ends with "pause" when the program fails and it believes it was double-clicked
    # (which is how cmd looks when PowerShell starts a .bat). An empty stdin answers the pause.
    '' | & $launch @all *>&1 | Out-File -FilePath $log -Encoding utf8
}
finally {
    $ErrorActionPreference = $prevEAP
    if ($null -eq $prevXdg) { Remove-Item Env:\XDG_CONFIG_HOME -ErrorAction SilentlyContinue }
    else { $env:XDG_CONFIG_HOME = $prevXdg }
    Remove-Item -Recurse -Force $settingsRoot -ErrorAction SilentlyContinue
}

Get-Content $log | Where-Object { $_ -match '^(CHECK |TOOL_TEST_|SCREENSHOT |  showing:)' } | ForEach-Object {
    if ($_ -match ': FAIL|RESULT FAIL')  { Write-Host $_ -ForegroundColor Red }
    elseif ($_ -match ': PASS')          { Write-Host $_ -ForegroundColor Green }
    else                                 { Write-Host $_ }
}
if (Select-String -Path $log -Pattern '^TOOL_TEST_RESULT PASS' -Quiet) {
    Write-Host "==> RESULT: PASS" -ForegroundColor Green; exit 0
} else {
    Write-Host "==> RESULT: FAIL (see $log)" -ForegroundColor Red; exit 1
}
