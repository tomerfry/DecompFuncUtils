# Rebuild the angr emulation fixture for run_angr_test.ps1.
# Requires clang + lld on PATH. The built ELF is committed, so only rerun this if you change
# angr_demo.c.
#
# -shared gives real PLT/GOT imports for the libc calls without needing a libc to link against;
# -O0 keeps one basic block per source branch; no -g, so Ghidra knows no signatures;
# -fno-builtin keeps the libc calls as calls; -fno-stack-protector keeps the prologues free
# of TLS canary reads.
$ErrorActionPreference = "Stop"
$dir = $PSScriptRoot

& clang -target x86_64-linux-gnu -shared -fPIC -nostdlib -fuse-ld=lld `
    -O0 -fno-builtin -fno-stack-protector `
    '-Wl,-soname,libangrdemo.so' `
    (Join-Path $dir "angr_demo.c") -o (Join-Path $dir "libangrdemo.so")
if ($LASTEXITCODE -ne 0) { throw "clang failed" }

Write-Host "Built libangrdemo.so"

# Seeking a destination from a session started with no arguments (AngrSeekHeadlessTest.java).
& clang -target x86_64-linux-gnu -shared -fPIC -nostdlib -fuse-ld=lld `
    -O0 -fno-builtin -fno-stack-protector `
    '-Wl,-soname,libangrseek.so' `
    (Join-Path $dir "angr_seek.c") -o (Join-Path $dir "libangrseek.so")
if ($LASTEXITCODE -ne 0) { throw "clang failed" }

Write-Host "Built libangrseek.so"

# The cross-module pair: a library, and a module that imports functions and a variable from it.
& clang -target x86_64-linux-gnu -shared -fPIC -nostdlib -fuse-ld=lld `
    -O0 -fno-builtin -fno-stack-protector `
    '-Wl,-soname,libangrxdep.so' `
    (Join-Path $dir "angr_xdep.c") -o (Join-Path $dir "libangrxdep.so")
if ($LASTEXITCODE -ne 0) { throw "clang failed" }
& clang -target x86_64-linux-gnu -shared -fPIC -nostdlib -fuse-ld=lld `
    -O0 -fno-builtin -fno-stack-protector `
    '-Wl,-soname,libangrxmain.so' `
    (Join-Path $dir "angr_xmain.c") (Join-Path $dir "libangrxdep.so") -o (Join-Path $dir "libangrxmain.so")
if ($LASTEXITCODE -ne 0) { throw "clang failed" }

Write-Host "Built libangrxdep.so and libangrxmain.so"
