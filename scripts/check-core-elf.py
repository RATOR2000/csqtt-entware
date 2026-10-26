#!/usr/bin/env python3
"""Reject the wrong ABI or libc before a binary reaches the router."""
import re
import subprocess
import sys

path = sys.argv[1]
def readelf(*args):
    return subprocess.check_output(['mipsel-linux-gnu-readelf', *args, path], text=True)

headers = readelf('-h', '-A', '-l')
for expected in ('ELF32', 'little endian', 'MIPS', 'o32', 'mips32r2', 'Soft float', '/opt/lib/ld.so.1'):
    if expected not in headers:
        raise SystemExit(f'ABI rejection: missing {expected!r} in {path}')
versions = readelf('--version-info')
required = {tuple(map(int, value.split('.'))) for value in re.findall(r'GLIBC_(\d+(?:\.\d+)+)', versions)}
if any(version > (2, 27) for version in required):
    raise SystemExit(f'ABI rejection: glibc newer than 2.27 required: {sorted(required)}')
dynamic = readelf('-d')
if re.search(r'NEEDED.*\[(?:libstdc\+\+|libatomic)', dynamic):
    raise SystemExit('ABI rejection: unexpected C++ or libatomic runtime dependency')
print(f'ABI verified: ELF32 MIPS32r2 LE O32 soft-float; glibc {max(required, default=(0,))}; /opt loader')
