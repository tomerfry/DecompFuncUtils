# Rebuild the cross-module link fixtures for run_resolve_externals_test.ps1.
# Requires clang + lld on PATH. The built ELFs are committed, so only rerun this
# if you change the .c files.
#
# testmain gets DT_NEEDED [libtestdep.so.1] plus UND dynsym entries for both functions;
# libtestdep.so.1 defines and exports them. -nostdlib keeps both tiny and free of libc.
$ErrorActionPreference = "Stop"
$dir = $PSScriptRoot

& clang -target x86_64-linux-gnu -shared -fPIC -nostdlib -fuse-ld=lld `
    -Wl,-soname,libtestdep.so.1 `
    (Join-Path $dir "libtestdep.c") -o (Join-Path $dir "libtestdep.so.1")

& clang -target x86_64-linux-gnu -nostdlib -fuse-ld=lld -pie `
    (Join-Path $dir "testmain.c") (Join-Path $dir "libtestdep.so.1") `
    -o (Join-Path $dir "testmain")

Write-Host "Built libtestdep.so.1 and testmain"
