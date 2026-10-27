#!/usr/bin/env python3
"""Create a deterministic Entware IPK from already-built MIPS executables."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
from pathlib import Path
import re
import struct
import tarfile

ROOT = Path(__file__).resolve().parents[1]
ARCH = "mipsel-3.4"


def mips_elf(path: Path) -> bytes:
    data = path.read_bytes()
    if len(data) < 52 or data[:7] != b"\x7fELF\x01\x01\x01":
        raise ValueError(f"{path.name}: expected 32-bit little-endian ELF")
    elf_type, machine = struct.unpack_from("<HH", data, 16)
    if machine != 8 or elf_type not in (2, 3):
        raise ValueError(f"{path.name}: expected MIPS executable")
    # MIPS64 instruction sets cannot execute on this MIPS32r2 target. Exact
    # soft-float, libc, TLS and CPU qualification remains the build gate.
    isa = struct.unpack_from("<I", data, 36)[0] & 0xF0000000
    if isa not in (0, 0x10000000, 0x50000000, 0x70000000):
        raise ValueError(f"{path.name}: incompatible MIPS instruction set")
    return data


def tar_gz(entries: list[tuple[str, bytes, int]], *, ordered: bool = False) -> bytes:
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", mtime=0, filename="") as zipped:
        with tarfile.open(fileobj=zipped, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, data, mode in entries if ordered else sorted(entries):
                info = tarfile.TarInfo(name)
                info.size, info.mode, info.mtime = len(data), mode, 0
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                archive.addfile(info, io.BytesIO(data))
    return output.getvalue()


def build(core: Path, manager: Path, version: str) -> bytes:
    if not re.fullmatch(r"[0-9][0-9A-Za-z.+~_-]{0,63}", version):
        raise ValueError("invalid package version")
    payloads = [("opt/bin/csqtt-client", mips_elf(core), 0o755),
                ("opt/bin/csqtt-entware", mips_elf(manager), 0o755),
                ("opt/etc/init.d/S90csqtt", (ROOT / "packaging/S90csqtt").read_bytes(), 0o755)]
    for source, name in [("LICENSE", "LICENSE"), ("THIRD_PARTY.md", "THIRD_PARTY.md")]:
        payloads.append(("opt/share/licenses/csqtt-entware/" + name, (ROOT / source).read_bytes(), 0o644))
    for module in ("golang.zx2c4.com/wireguard", "golang.zx2c4.com/wintun",
                   "golang.org/x/crypto", "golang.org/x/net", "golang.org/x/sys"):
        payloads.append(("opt/share/licenses/csqtt-entware/" + module + "/LICENSE",
                         (ROOT / "vendor" / module / "LICENSE").read_bytes(), 0o644))
    control = (f"Package: csqtt-entware\nVersion: {version}\nArchitecture: {ARCH}\n"
               "Maintainer: CSQTT Entware contributors\nSection: net\nPriority: optional\n"
               "License: PolyForm-Noncommercial-1.0.0\n"
               "Depends: libc (>= 2.27), libgcc, libpthread, librt\n"
               f"Installed-Size: {sum(len(data) for _, data, _ in payloads)}\n"
               "Description: CSQTT 2.1.9 client with a local WireGuard packet bridge and LAN manager\n").encode()
    # All files under /opt/etc/csqtt are generated owner data, never package
    # payloads. opkg cannot replace settings/identity/keys on upgrade or remove.
    controls = [("control", control, 0o644)]
    for name in ("preinst", "postinst", "prerm", "postrm"):
        controls.append((name, (ROOT / "packaging" / name).read_bytes(), 0o755))
    # Entware uses a gzip-compressed outer tar, unlike Debian's ar container.
    # Match the official feed's three-member IPK convention and retain order.
    return tar_gz([
        ("./debian-binary", b"2.0\n", 0o644),
        ("./control.tar.gz", tar_gz(controls), 0o644),
        ("./data.tar.gz", tar_gz(payloads), 0o644),
    ], ordered=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", type=Path, default=ROOT / "dist/csqtt-client")
    parser.add_argument("--manager", type=Path, default=ROOT / "dist/csqtt-entware")
    parser.add_argument("--version", default="0.1.0~dev1")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output = args.output or ROOT / f"dist/csqtt-entware_{args.version}_{ARCH}.ipk"
    package = build(args.core, args.manager, args.version)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(package)
    digest = hashlib.sha256(package).hexdigest()
    output.with_name(output.name + ".sha256").write_text(f"{digest}  {output.name}\n", encoding="ascii")
    print(f"{output.name}: {digest}")


if __name__ == "__main__":
    main()
