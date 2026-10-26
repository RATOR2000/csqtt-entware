#!/usr/bin/env bash
# Cross-compile using a host GCC and the official Entware soft-float sysroot.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
work=${CSQTT_BUILD_DIR:-"$root/.work/core-build"}
rust_version=1.97.1
target=mipsel-entware-linux-gnu
gcc_ipk=gcc_8.4.0-8_mipsel-3.4.ipk
gcc_sha=f442e7d702ef25f6689d386ebb3ff6586d19a2ce8fdeaf32925c1713e3febf89
mkdir -p "$work/downloads" "$work/sysroot" "$work/bin" "$root/dist"
if [ ! -f "$work/downloads/$gcc_ipk" ]; then
  curl --fail --location --retry 3 "https://bin.entware.net/mipselsf-k3.4/$gcc_ipk" -o "$work/downloads/$gcc_ipk"
fi
printf '%s  %s\n' "$gcc_sha" "$work/downloads/$gcc_ipk" | sha256sum -c -
if [ ! -f "$work/sysroot/.ready-$gcc_sha" ]; then
  tar -xOf "$work/downloads/$gcc_ipk" ./data.tar.gz | tar -xz -C "$work/sysroot"
  gcc_lib="$work/sysroot/opt/lib/gcc/mipsel-openwrt-linux-gnu/8.4.0"
  # Do not pass -B pointing to the native GCC directory: it contains MIPS cc1
  # executables. Only its ABI-matched startup objects and libraries are used.
  find "$gcc_lib" -maxdepth 1 \( -name '*.o' -o -name '*.a' -o -name '*.so*' \) ! -name 'liblto_plugin*' -exec cp -a '{}' "$work/sysroot/opt/lib/" \;
  touch "$work/sysroot/.ready-$gcc_sha"
fi
export CSQTT_ENTWARE_SYSROOT="$work/sysroot"
cat > "$work/bin/entware-gcc" <<'WRAPPER'
#!/usr/bin/env bash
set -euo pipefail
cc=mipsel-linux-gnu-gcc
if [[ ${0##*/} == *g++ ]]; then cc=mipsel-linux-gnu-g++; fi
builtin_include=$($cc -print-file-name=include)
exec "$cc" --sysroot="$CSQTT_ENTWARE_SYSROOT" \
  -mips32r2 -mabi=32 -msoft-float -mno-branch-likely -fno-use-linker-plugin \
  -B"$CSQTT_ENTWARE_SYSROOT/opt/lib/" \
  -nostdinc -isystem "$builtin_include" -isystem "$CSQTT_ENTWARE_SYSROOT/opt/include" \
  -L"$CSQTT_ENTWARE_SYSROOT/opt/lib" \
  -Wl,-rpath-link,"$CSQTT_ENTWARE_SYSROOT/opt/lib" \
  -Wl,--dynamic-linker=/opt/lib/ld.so.1 -Wl,-rpath,/opt/lib "$@"
WRAPPER
chmod +x "$work/bin/entware-gcc"
ln -sf entware-gcc "$work/bin/entware-g++"
command -v mipsel-linux-gnu-gcc >/dev/null
command -v mipsel-linux-gnu-readelf >/dev/null
export RUSTUP_TOOLCHAIN="$rust_version"
rustc --version
export RUSTC_BOOTSTRAP=1
rustc -Z unstable-options --print target-spec-json --target mipsel-unknown-linux-gnu > "$work/base-target.json"
python3 - "$work/base-target.json" "$root/targets/$target.json" "$work/$target.json" "$work/bin/entware-gcc" <<'PY'
import json,sys
base=json.load(open(sys.argv[1]))
base.update(json.load(open(sys.argv[2])))
base['linker']=sys.argv[4]
json.dump(base,open(sys.argv[3],'w'),indent=2)
PY
export CC_mipsel_entware_linux_gnu="$work/bin/entware-gcc"
export CXX_mipsel_entware_linux_gnu="$work/bin/entware-g++"
export AR_mipsel_entware_linux_gnu=mipsel-linux-gnu-ar
export CFLAGS_mipsel_entware_linux_gnu='-O2 -mips32r2 -mabi=32 -msoft-float'
export CXXFLAGS_mipsel_entware_linux_gnu="$CFLAGS_mipsel_entware_linux_gnu"
export CARGO_TARGET_DIR="$work/target"
export CARGO_TARGET_MIPSEL_ENTWARE_LINUX_GNU_LINKER="$work/bin/entware-gcc"
export CARGO_TARGET_MIPSEL_ENTWARE_LINUX_GNU_RUSTFLAGS='-C link-arg=-Wl,--hash-style=both'
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-2}
printf '#include <stdio.h>\nint main(void){puts("entware-softfloat");return 0;}\n' > "$work/abi-smoke.c"
"$work/bin/entware-gcc" "$work/abi-smoke.c" -o "$work/abi-smoke"
python3 "$root/scripts/check-core-elf.py" "$work/abi-smoke"
cargo build --manifest-path "$root/vendor/csqtt/rust-client/Cargo.toml" \
  --locked --release --target "$work/$target.json" -Z build-std=std,panic_unwind
core="$work/target/$target/release/client"
python3 "$root/scripts/check-core-elf.py" "$core"
cp "$core" "$root/dist/csqtt-client"
sha256sum "$root/dist/csqtt-client" > "$root/dist/csqtt-client.sha256"
