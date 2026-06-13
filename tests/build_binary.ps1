# Recompile tests/test_vuln.o from test_vuln.c (x86-64 Linux ELF object).
# Requires clang on PATH. The committed .o is what the test imports, so only
# rerun this if you change test_vuln.c.
$ErrorActionPreference = "Stop"
$dir = $PSScriptRoot
& clang -target x86_64-linux-gnu -c -O0 -g -fno-stack-protector `
    (Join-Path $dir "test_vuln.c") -o (Join-Path $dir "test_vuln.o")
Write-Host "Built test_vuln.o"
