# Rebuild the refinement-engine fixture for run_refine_test.ps1.
# Requires clang + lld on PATH. The built ELF is committed, so only rerun this if you change
# refine_demo.c.
#
# -O2 is the point: the engine undoes what the optimizer did. -fno-builtin keeps the open-coded
# loops as loops (otherwise clang turns them back into libc calls itself); the vectorizer and
# unroller are off so each loop stays one recognizable scalar loop; no -g, so Ghidra knows no
# signatures or names beyond the exported symbols.
$ErrorActionPreference = "Stop"
$dir = $PSScriptRoot

& clang -target x86_64-linux-gnu -shared -fPIC -nostdlib -fuse-ld=lld `
    -O2 -fno-builtin -fno-stack-protector -fno-vectorize -fno-slp-vectorize -fno-unroll-loops `
    '-Wl,-soname,librefinedemo.so' `
    (Join-Path $dir "refine_demo.c") -o (Join-Path $dir "librefinedemo.so")
if ($LASTEXITCODE -ne 0) { throw "clang failed" }

Write-Host "Built librefinedemo.so"
