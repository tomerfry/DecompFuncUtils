<#
.SYNOPSIS
  Open the "angr Debugger" tool for real - a Ghidra tool window, not a headless run - and check
  it. Exits 0 on PASS, 1 on FAIL, 2 when it cannot run.

.DESCRIPTION
  Everything the headless tests cannot reach lives in a window: the tool file itself, docking,
  the program counter and breakpoints drawn in the Listing, the menu and its key bindings. This
  runner starts decompfuncutils.angr.ui.AngrDebuggerToolPreview through Ghidra's own launcher,
  which opens the tool exactly as shipped on tests/angr/libangrdemo.so, drives a debug session
  through it, prints CHECK lines, and leaves pictures of the window in tests/_angr_tool_*.png.

  The window is placed off-screen and never takes focus, so it does not get in the way; it is
  painted into the pictures rather than looked at.

  -Export regenerates the shipped tool file (src/main/resources/defaultTools/angr_Debugger.tool)
  first: Ghidra builds the tool from its plugin packages, lays the windows out, and the result is
  saved. Do this whenever the plugin's windows change or the extension gains a plugin.

  Like the other runners this installs the build into a temporary settings tree, so a running
  Ghidra keeps its own copy and is left alone.
#>
[CmdletBinding()]
param(
    [string]$GhidraInstall = $(if ($env:GHIDRA_INSTALL_DIR) { $env:GHIDRA_INSTALL_DIR } else { "C:\Users\User\Ghidra" }),
    [switch]$SkipBuild,
    [string]$GradleExe = "gradle",
    [string]$Python = "",
    [string]$WorkRoot = $env:TEMP,
    # Regenerate the shipped tool file before checking it.
    [switch]$Export
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$launch = Join-Path $GhidraInstall "support\launch.bat"
if (-not (Test-Path $launch)) { Write-Error "launch.bat not found at $launch (set GHIDRA_INSTALL_DIR)"; exit 2 }
$fixture = Join-Path $repo "tests\angr\libangrdemo.so"
$toolFile = Join-Path $repo "src\main\resources\defaultTools\angr_Debugger.tool"

if (-not $Python) {
    $pointer = Join-Path $HOME ".decompfuncutils\angr-python"
    if ($env:DFU_ANGR_PYTHON) { $Python = $env:DFU_ANGR_PYTHON }
    elseif (Test-Path -LiteralPath $pointer) { $Python = (Get-Content -LiteralPath $pointer -Raw).Trim() }
}
if (-not $Python -or -not (Test-Path -LiteralPath $Python)) {
    Write-Error "No Python with angr is set up. Run tools\setup-angr.ps1 first, or pass -Python."; exit 2
}

function Build {
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
$scratch = Join-Path $WorkRoot "dfu_angr_tool_$runId"

function Install {
    $zip = Get-ChildItem (Join-Path $repo "dist\*DecompFuncUtils*.zip") | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $zip) { throw "No built extension zip in dist/" }
    Remove-Item -Recurse -Force $extDir -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force $extDir | Out-Null
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zip.FullName, $extDir)
    Write-Host "==> Installed $($zip.Name)" -ForegroundColor Cyan
}

function Preview([string[]]$previewArgs, [string]$log) {
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        # The VM-argument slot must not be empty (PowerShell drops an empty argument and
        # launch.bat would take the class name for it) and must not contain '=', which cmd
        # splits arguments on. A property nobody reads fits both.
        $all = @('fg', 'jdk', 'AngrDebuggerToolPreview', '2G', '-Ddfu.angr.preview',
            'decompfuncutils.angr.ui.AngrDebuggerToolPreview') + $previewArgs
        & $launch @all *>&1 | Out-File -FilePath $log -Encoding utf8
    }
    finally { $ErrorActionPreference = $prevEAP }
}

$saved = @{}
foreach ($name in 'XDG_CONFIG_HOME', 'DFU_ANGR_PYTHON', 'DFU_ANGR_TMP', 'DFU_ANGR_HOOKS') {
    $saved[$name] = [Environment]::GetEnvironmentVariable($name)
}
New-Item -ItemType Directory -Force $scratch | Out-Null
$log = Join-Path $repo "tests\_last_AngrDebuggerTool_run.log"
try {
    if (-not $SkipBuild) { Build }
    Install
    $env:XDG_CONFIG_HOME = $settingsRoot
    $env:DFU_ANGR_PYTHON = $Python
    $env:DFU_ANGR_TMP = $scratch
    $env:DFU_ANGR_HOOKS = Join-Path $scratch "hooks"

    if ($Export) {
        Write-Host "==> Exporting the tool file..." -ForegroundColor Cyan
        New-Item -ItemType Directory -Force (Split-Path -Parent $toolFile) | Out-Null
        $exportLog = Join-Path $repo "tests\_last_AngrDebuggerTool_export.log"
        Preview @('export', $toolFile) $exportLog
        $line = Select-String -Path $exportLog -Pattern '^EXPORTED ' | Select-Object -First 1
        if (-not $line) { Write-Host "==> Export failed (see $exportLog)" -ForegroundColor Red; exit 1 }
        Write-Host $line.Line
        # The exported picture sits next to the tool file; it belongs with the test output.
        $picture = Join-Path (Split-Path -Parent $toolFile) "_angr_tool_export.png"
        if (Test-Path $picture) { Move-Item -Force $picture (Join-Path $repo "tests\_angr_tool_export.png") }
        Build
        Install
    }

    Write-Host "==> Opening the tool..." -ForegroundColor Cyan
    Preview @('check', (Join-Path $repo "tests"), $fixture) $log
}
finally {
    foreach ($name in $saved.Keys) { [Environment]::SetEnvironmentVariable($name, $saved[$name]) }
    Remove-Item -Recurse -Force $settingsRoot, $scratch -ErrorAction SilentlyContinue
}

Get-Content $log | Where-Object { $_ -match '^(CHECK |TOOL_TEST_|  showing:)' } | ForEach-Object {
    if ($_ -match ': FAIL|RESULT FAIL')  { Write-Host $_ -ForegroundColor Red }
    elseif ($_ -match ': PASS')          { Write-Host $_ -ForegroundColor Green }
    else                                 { Write-Host $_ }
}
if (Select-String -Path $log -Pattern '^TOOL_TEST_RESULT PASS' -Quiet) {
    Write-Host "==> RESULT: PASS" -ForegroundColor Green; exit 0
} else {
    Write-Host "==> RESULT: FAIL (see $log)" -ForegroundColor Red; exit 1
}
