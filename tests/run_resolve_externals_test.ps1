<#
.SYNOPSIS
  Build the extension, install the fresh build into an isolated settings tree, and run the
  headless regression test for ghidra_resolve_externals. Exits 0 on PASS, 1 on FAIL.

.NOTES
  Imports tests/extlink/libtestdep.so.1 and tests/extlink/testmain into one throwaway project
  with analysis OFF — the ELF loader alone produces the UND imports and the library's exported
  entry points, so the run takes seconds. Rebuild the fixtures with tests/extlink/build.ps1
  (needs clang + lld); the built ELFs are committed so the test does not need a compiler.

  Like run_headless_test.ps1, this installs into a temporary XDG_CONFIG_HOME so a running GUI
  Ghidra (and its live MCP server) keeps its own jar and is left untouched.
#>
[CmdletBinding()]
param(
    [string]$GhidraInstall = $(if ($env:GHIDRA_INSTALL_DIR) { $env:GHIDRA_INSTALL_DIR } else { "C:\Users\User\Ghidra" }),
    [switch]$SkipBuild,
    # Gradle 9.1+ is required by Ghidra 12.2's buildExtension.gradle; override if `gradle`
    # on PATH is older.
    [string]$GradleExe = "gradle",
    # ResolveExternalsHeadlessTest.java (default, import -> library linking) or
    # BacklinkImportsHeadlessTest.java (cross-module back-links written into the library).
    [string]$Script = 'ResolveExternalsHeadlessTest.java',
    # Where the throwaway settings tree and project go. Defaults to TEMP; point it at a drive
    # with room (e.g. D:\temp) when the system drive is tight - the installed extension and the
    # project together need a few hundred MB.
    [string]$WorkRoot = $env:TEMP,
    # Run auto-analysis on the imports. Off by default: external symbols and exported entry
    # points come from the ELF loader, so the linking test needs no analysis and runs in seconds.
    # The back-link test DOES need it - call sites only exist once the callers are disassembled.
    [switch]$Analyze
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$hl   = Join-Path $GhidraInstall "support\analyzeHeadless.bat"
if (-not (Test-Path $hl)) { Write-Error "analyzeHeadless not found at $hl (set GHIDRA_INSTALL_DIR)"; exit 2 }

$lib  = Join-Path $repo "tests\extlink\libtestdep.so.1"
$main = Join-Path $repo "tests\extlink\testmain"
foreach ($f in @($lib, $main)) {
    if (-not (Test-Path -LiteralPath $f)) {
        Write-Error "Missing fixture $f - run tests\extlink\build.ps1"; exit 2
    }
}

# 1) Build the extension.
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

# 2) Freshest dist zip (a worktree builds e.g. DecompFuncUtils.improve.zip - match either).
$zip = Get-ChildItem (Join-Path $repo "dist\*DecompFuncUtils*.zip") | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $zip) { Write-Error "No built extension zip in dist/"; exit 2 }

# 3) Isolated settings dir, so a running Ghidra never has its jar replaced underneath it.
#    The path under XDG_CONFIG_HOME has to match what Ghidra computes, or the extension is
#    simply not found and every script importing it fails to resolve with
#    "missing requirement osgi.wiring.package=decompfuncutils...". Read all three parts from
#    the install rather than hardcoding them: layout version 3 (Ghidra 12.3+) prefixes the
#    parent directory with the user name -- "User-ghidra" instead of "ghidra".
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

# 4) Import both binaries into one throwaway project, library first so it is already
#    in the project when the post-script runs for the importer. Without -Analyze this uses
#    -noanalysis and runs in seconds: external symbols and exported entry points both come
#    from the ELF loader. Pass -Analyze when the test needs call sites, which only exist
#    once the calling code has been disassembled.
$analysisArgs = if ($Analyze) { @() } else { @('-noanalysis') }
$proj = Join-Path $WorkRoot "dfu_ghidra_proj_$runId"
New-Item -ItemType Directory -Force $proj | Out-Null
$sp  = Join-Path $repo "tests\scripts"
$log = Join-Path $repo ("tests\_last_" +
    [System.IO.Path]::GetFileNameWithoutExtension($Script) + "_run.log")

Write-Host "==> Running headless test..." -ForegroundColor Cyan
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$prevXdg = $env:XDG_CONFIG_HOME
$env:XDG_CONFIG_HOME = $settingsRoot
# Assemble the arguments as one array. Splatting mid-line and continuing with a backtick --
# "-import $main @analysisArgs `" -- makes Windows PowerShell 5.1 expand the array one
# CHARACTER per argument ("- n o a n a l y s i s"), so Ghidra sees "-" as a file to import.
$hlArgs = @($proj, 'T', '-import', $lib, '-import', $main) +
    $analysisArgs +
    @('-scriptPath', $sp, '-postScript', $Script, '-deleteProject')
try {
    & $hl @hlArgs *>&1 | Out-File -FilePath $log -Encoding utf8
}
finally {
    if ($null -eq $prevXdg) { Remove-Item Env:\XDG_CONFIG_HOME -ErrorAction SilentlyContinue }
    else { $env:XDG_CONFIG_HOME = $prevXdg }
    Remove-Item -Recurse -Force $settingsRoot -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $proj -ErrorAction SilentlyContinue
}
$ErrorActionPreference = $prevEAP

# 5) Report.
$lines = Get-Content $log | Where-Object { $_ -match 'CHECK |HEADLESS_TEST_SUMMARY|HEADLESS_TEST_RESULT|DRY |REAL |REMOVE ' }
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
