# Rust core: Entware MIPS build

The core retains original CSQTT 2.1.9 compatibility. Its wire protocol and VK
authentication fingerprint are unchanged. See `THIRD_PARTY.md` for source
provenance and license notices.

## Toolchain

The target is MIPS32r2 little-endian O32, soft-float, Linux, dynamically linked
against Entware glibc 2.27. The executable interpreter is
`/opt/lib/ld.so.1`, with an `/opt/lib` runtime library search path.

`scripts/build-core.sh` uses:

- Rust **1.97.1**, including the matching Rust standard-library sources.
- A custom target derived from that compiler's built-in MIPS target, overridden
  by `targets/mipsel-entware-linux-gnu.json`. The standard library is rebuilt
  with `-Z build-std`; JSON target support is explicitly enabled.
- A host `mipsel-linux-gnu-gcc` cross compiler. Startup objects, headers and
  libraries come from the official Entware `gcc_8.4.0-8_mipsel-3.4.ipk`, checked
  against SHA-256 `f442e7d702ef25f6689d386ebb3ff6586d19a2ce8fdeaf32925c1713e3febf89`.
- The committed Cargo lockfile and retained local `primp` source.

The native MIPS GCC programs from that package are never executed by the build
host. The wrapper isolates the Entware sysroot and excludes the native LTO
plugin. `scripts/check-core-elf.py` rejects the wrong architecture, byte order,
floating-point ABI, loader or a glibc symbol requirement newer than 2.27.

The application uses `portable-atomic` for its 64-bit counters and generations.
The MIPS target advertises only 32-bit hardware atomics, so the crate uses its
safe fallback. Counter widths and memory ordering are preserved.

## Build on Linux

The reference build environment is Ubuntu 24.04. Install the host cross tools
and the pinned Rust sources, then run:

```sh
sudo apt-get update
sudo apt-get install -y gcc-mipsel-linux-gnu g++-mipsel-linux-gnu \
  binutils-mipsel-linux-gnu qemu-user
rustup toolchain install 1.97.1 --profile minimal --component rust-src
CSQTT_BUILD_TESTS=1 bash scripts/build-core.sh
```

Downloads, the Entware sysroot and compilation cache stay under `.work/`.
The output is `dist/csqtt-client` and `dist/csqtt-client.sha256`.
The compiler, dependency and ABI inputs are constrained as above; bit-for-bit
reproducibility across future host package revisions has not been qualified.

## Verified checkpoint

[Actions run 40373706420](https://github.com/RATOR2000/csqtt-entware/actions/runs/40373706420)
at commit `2cf990df629cef8e6632b432cf4d09a65b756958` passed both jobs:

- Host Rust tests: **381 passed, 0 failed, 7 ignored**. The inherited ignored
  tests remain explicitly separate from executed tests.
- MIPS cross compilation and ELF ABI inspection: passed, with a highest glibc
  symbol requirement of **2.27**.
- QEMU MIPS checks: the C ABI startup program, the core's missing-configuration
  startup path, the 64-bit atomic contention test, the known wire-format crypto
  vector, and the Go-compatible audio/video obfuscation vectors all passed.

The `csqtt-client-entware-mipsel` artifact from this run contains the core:

```text
SHA-256 51aca29706d6ed28dd6dba3b3be05ced9f6338b501e5c15e563b2d7aeeb31dec
```

These results establish compilation, ABI and the named emulated checks. They
do not establish real router operation, VK authorization, Internet traffic,
memory headroom, throughput, or fail-closed behavior. Native and end-to-end
qualification is recorded separately in `STATUS.md` and the acceptance plan.
