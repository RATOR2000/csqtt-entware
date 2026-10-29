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
  --locked --release --target "$work/$target.json" -Z build-std=std,panic_unwind -Z json-target-spec
core="$work/target/$target/release/client"
python3 "$root/scripts/check-core-elf.py" "$core"
cp "$core" "$root/dist/csqtt-client"
(cd "$root/dist" && sha256sum csqtt-client > csqtt-client.sha256)
if [ "${CSQTT_BUILD_TESTS:-0}" = 1 ]; then
  cargo test --manifest-path "$root/vendor/csqtt/rust-client/Cargo.toml" \
    --locked --release --no-run --message-format=json \
    --target "$work/$target.json" -Z build-std=std,panic_unwind -Z json-target-spec > "$work/test-artifacts.jsonl"
  test_exe=$(python3 - "$work/test-artifacts.jsonl" <<'PY'
import json,sys
for line in open(sys.argv[1]):
    event=json.loads(line)
    if (event.get('reason')=='compiler-artifact' and event.get('profile',{}).get('test')
        and event.get('target',{}).get('name')=='client' and event.get('executable')):
        print(event['executable'])
        break
else:
    raise SystemExit('No MIPS test executable was built')
PY
  )
  python3 "$root/scripts/check-core-elf.py" "$test_exe"
  for test_name in \
    entropy::tests::operating_system_entropy_and_uuid_are_available \
    daemon::tests::persistent_identity_survives_restart_and_locks_parallel_instances \
    daemon::tests::captcha_auto_attempts_default_and_bounds \
    captcha::tests::daemon_manual_first_skips_auto_and_keeps_answer_before_wait \
    captcha::tests::daemon_manual_first_retains_unclaimed_fresh_auth_deadline \
    captcha::tests::daemon_automatic_attempts_still_deliver_success \
    atomic::tests::portable_generations_cross_32_bits_under_contention \
    wrap::tests::known_wire_vector \
    obfs::tests::unwraps_go_audio_and_video_vectors; do
    timeout 90 qemu-mipsel "$work/sysroot/opt/lib/ld.so.1" \
      --library-path "$work/sysroot/opt/lib" "$test_exe" --exact "$test_name"
  done
fi
python3 "$root/scripts/notices.py" core --binary "$root/dist/csqtt-client" \
  --target "$work/$target.json" --output "$root/dist/csqtt-client-notices.tar.gz"
