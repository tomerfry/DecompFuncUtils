<#
.SYNOPSIS
  Create the private Python environment the ghidra_angr_emulate MCP tool runs angr in.

.DESCRIPTION
  angr pins exact versions of a large dependency tree, so installing it into a shared Python
  tends to break either angr or whatever else lives there. This creates a virtual environment
  used for nothing else, installs angr into it, checks that it imports, and records the
  interpreter in ~/.decompfuncutils/angr-python, which is where the Ghidra extension looks.
  A running Ghidra picks it up on the next tool call - no restart.

  Safe to re-run: an existing environment is reused and angr is upgraded only with -Upgrade.

.EXAMPLE
  .\tools\setup-angr.ps1
  .\tools\setup-angr.ps1 -Path D:\tools\angr-venv      # when the home drive is short of space (~450 MB)
#>
[CmdletBinding()]
param(
    # Where the environment goes. Needs roughly 450 MB.
    [string]$Path = (Join-Path $HOME ".decompfuncutils\angr-venv"),
    # The Python used to create it (3.10 or newer).
    [string]$Python = "python",
    # Upgrade angr in an existing environment.
    [switch]$Upgrade
)

$ErrorActionPreference = "Stop"
$venvPython = Join-Path $Path "Scripts\python.exe"

if (-not (Test-Path -LiteralPath $venvPython)) {
    Write-Host "==> Creating virtual environment in $Path" -ForegroundColor Cyan
    & $Python -m venv $Path
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $venvPython)) {
        throw "Could not create a virtual environment with '$Python'. Pass -Python <path to python 3.10+>."
    }
}

# Is angr already importable? (Its import prints warnings on stderr; only the exit code matters.)
$prev = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& $venvPython -c "import angr" 2>$null | Out-Null
$haveAngr = ($LASTEXITCODE -eq 0)
$ErrorActionPreference = $prev

if (-not $haveAngr -or $Upgrade) {
    Write-Host "==> Installing angr (a few hundred MB, this takes a few minutes)" -ForegroundColor Cyan
    $pipArgs = @("-m", "pip", "install", "--disable-pip-version-check", "--no-cache-dir")
    if ($Upgrade) { $pipArgs += "--upgrade" }
    $pipArgs += "angr"
    & $venvPython @pipArgs
    if ($LASTEXITCODE -ne 0) { throw "pip install angr failed" }
}

$ErrorActionPreference = "Continue"
$version = & $venvPython -c "import angr; print(angr.__version__)" 2>$null
$ok = ($LASTEXITCODE -eq 0)
$ErrorActionPreference = $prev
if (-not $ok) { throw "angr was installed but does not import. Run: `"$venvPython`" -c `"import angr`"" }

$pointerDir = Join-Path $HOME ".decompfuncutils"
New-Item -ItemType Directory -Force $pointerDir | Out-Null
$pointer = Join-Path $pointerDir "angr-python"
# No byte-order mark: the Java side reads this as a bare path.
[System.IO.File]::WriteAllText($pointer, (Resolve-Path -LiteralPath $venvPython).Path, (New-Object System.Text.UTF8Encoding($false)))

Write-Host "==> angr $version is ready" -ForegroundColor Green
Write-Host "    interpreter: $venvPython"
Write-Host "    recorded in: $pointer"
