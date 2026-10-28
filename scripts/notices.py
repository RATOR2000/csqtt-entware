#!/usr/bin/env python3
"""Collect offline build notices and verify bounded, binary-bound notice bundles."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
MAX_FILE = 16 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
MAX_FILES = 4096
NOTICE = re.compile(r"^(?:licen[cs]e|copying|notice|copyright|authors|patents)(?:[._-].*)?$", re.I)
TEXT_MEMBER = re.compile(r"texts/[0-9a-f]{64}\.txt")
# The published subcrate omits the repository-root LICENSE. Its packaged
# .cargo_vcs_info.json pins this exact revision; never synthesize SPDX text.
CARGO_SUPPLEMENTS = {
    ("alloc-stdlib", "0.2.4", "0e76a019e91224d279006ff972f1e984179a6e9feb050adba6ce8274aef23195"): (
        "packaging/notices/alloc-stdlib-0.2.4/LICENSE",
        "c0c56f26d9c051cac4d200c34c84e7ae9aaa853e01a982a1df08b09931e518ae",
        "https://raw.githubusercontent.com/dropbox/rust-alloc-no-stdlib/ae42d22078b98549e987d2f03d12df7b984fde47/LICENSE"),
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def inputs(kind: str, root: Path = ROOT) -> dict[str, str]:
    names = ("vendor/csqtt/rust-client/Cargo.lock", "vendor/csqtt/rust-client/Cargo.toml",
             "vendor/csqtt/rust-client/vendor/primp/Cargo.toml",
             "vendor/csqtt/rust-client/vendor/primp/LICENSE-MIT") if kind == "core" else (
                 "go.mod", "go.sum", "vendor/modules.txt")
    if kind == "core":
        names += tuple(item[0] for item in CARGO_SUPPLEMENTS.values() if (root / item[0]).is_file())
    return {name: digest((root / name).read_bytes()) for name in names}


def safe_path(name: str) -> bool:
    return (bool(name) and len(name) <= 512 and "\\" not in name and ":" not in name
            and not any(ord(c) < 32 for c in name)
            and not name.startswith("/") and all(p not in ("", ".", "..") for p in name.split("/")))


def notice_files(directory: Path) -> list[Path]:
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("notice source must be a real directory")
    result = []
    for current, dirs, files in os.walk(directory, followlinks=False):
        dirs.sort()
        for name in dirs + files:
            if (Path(current) / name).is_symlink():
                raise ValueError("symlink in notice source")
        for name in sorted(files):
            path = Path(current) / name
            relative = path.relative_to(directory)
            if (directory.name.lower() in ("licenses", "licences") or NOTICE.fullmatch(name) or
                    any(p.lower() in ("licenses", "licences") for p in relative.parts[:-1])):
                result.append(path)
    return result


def component(name: str, version: str, source: str, license: str | None,
              directory: Path, files: list[Path], texts: dict[str, bytes]) -> dict:
    if not files:
        raise ValueError(f"missing notice files for {name} {version}")
    notices = []
    for path in sorted(set(files)):
        relative = path.relative_to(directory).as_posix()
        if not safe_path(relative) or path.is_symlink() or not path.is_file():
            raise ValueError("unsafe notice source path")
        # resolve() also rejects a symlink in a license_file parent.
        if not path.resolve().is_relative_to(directory.resolve()):
            raise ValueError("notice source escapes its component")
        if not 0 < path.stat().st_size <= MAX_FILE:
            raise ValueError("empty or oversized notice")
        data = path.read_bytes()
        member = f"texts/{digest(data)}.txt"
        texts[member] = data
        notices.append({"path": relative, "member": member, "sha256": digest(data)})
    return {"name": name, "version": version, "source": source,
            "license": license, "files": notices}


def cargo_components(metadata: dict, lock: dict, root: Path, texts: dict[str, bytes]) -> list[dict]:
    # Cargo's platform-filtered resolve graph includes host/build/test crates as
    # well as target crates. Keeping that conservative superset is intentional.
    selected = {node["id"] for node in metadata["resolve"]["nodes"]}
    locked = {(p["name"], p["version"], p.get("source")): p for p in lock["package"]}
    result = []
    for package in metadata["packages"]:
        if package["id"] not in selected:
            continue
        name, version, source = package["name"], package["version"], package.get("source")
        pinned = locked.get((name, version, source))
        if pinned is None:
            raise ValueError("Cargo metadata does not match the lockfile")
        directory = Path(package["manifest_path"]).parent
        files = notice_files(directory)
        if package.get("license_file"):
            license_path = package["license_file"]
            if not safe_path(license_path):
                raise ValueError("unsafe Cargo license_file")
            files.append(directory / license_path)
        if source is None:
            if not directory.resolve().is_relative_to(root.resolve()):
                raise ValueError("untracked Cargo path dependency")
            source = "path:" + directory.relative_to(root).as_posix()
            if name == "csqtt-client":
                directory, files = root / "vendor/csqtt", [root / "vendor/csqtt/LICENSE"]
        elif source != "registry+https://github.com/rust-lang/crates.io-index" or not pinned.get("checksum"):
            raise ValueError("unsupported or unverified Cargo source")
        supplement = CARGO_SUPPLEMENTS.get((name, version, pinned.get("checksum"))) if not files else None
        if supplement:
            path, expected, origin = supplement
            notice = root / path
            if digest(notice.read_bytes()) != expected:
                raise ValueError("supplemental upstream notice hash mismatch")
            directory, files = notice.parent, [notice]
        entry = component(name, version, source, package.get("license"), directory, files, texts)
        if supplement:
            entry["files"][0]["origin"] = supplement[2]
        if pinned.get("checksum"):
            entry["crate_sha256"] = pinned["checksum"]
        result.append(entry)
    if not result or len(result) != len(selected):
        raise ValueError("incomplete Cargo metadata graph")
    return sorted(result, key=lambda c: (c["name"], c["version"], c["source"]))


def bundle(kind: str, binary: Path, toolchain: str, source_revision: str,
           components: list[dict], texts: dict[str, bytes], root: Path = ROOT) -> bytes:
    manifest = {"format": "csqtt-notices-v1", "kind": kind,
                "binary_sha256": digest(binary.read_bytes()), "toolchain": toolchain,
                "source_revision": source_revision, "inputs": inputs(kind, root),
                "components": components}
    entries = {"manifest.json": (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode(), **texts}
    if len(entries) > MAX_FILES or sum(map(len, entries.values())) > MAX_TOTAL:
        raise ValueError("notice bundle is too large")
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", mtime=0, filename="") as zipped:
        with tarfile.open(fileobj=zipped, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, data in sorted(entries.items()):
                info = tarfile.TarInfo(name)
                info.size, info.mode = len(data), 0o644
                archive.addfile(info, io.BytesIO(data))
    data = output.getvalue()
    verify(data, kind, binary.read_bytes(), root)
    return data


def verify(data: bytes, kind: str, binary: bytes, root: Path = ROOT) -> dict[str, bytes]:
    if len(data) > MAX_TOTAL:
        raise ValueError("notice archive is too large")
    entries: dict[str, bytes] = {}
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r|gz") as archive:
            for item in archive:
                if (not item.isfile() or item.name in entries or
                    (item.name != "manifest.json" and not TEXT_MEMBER.fullmatch(item.name)) or
                    not 0 < item.size <= MAX_FILE or len(entries) >= MAX_FILES):
                    raise ValueError("unsafe notice archive member")
                total += item.size
                if total > MAX_TOTAL:
                    raise ValueError("notice archive expands beyond its limit")
                entries[item.name] = archive.extractfile(item).read()
        manifest = json.loads(entries["manifest.json"])
        if (manifest["format"] != "csqtt-notices-v1" or manifest["kind"] != kind or
            manifest["binary_sha256"] != digest(binary) or manifest["inputs"] != inputs(kind, root) or
            not re.fullmatch(r"[0-9a-f]{40}", manifest["source_revision"])):
            raise ValueError("notice provenance does not match binary/source inputs")
        runtime = "rust-runtime" if kind == "core" else "go-runtime"
        components = manifest["components"]
        names = [c["name"] for c in components]
        if names.count(runtime) != 1 or (kind == "core" and "csqtt-client" not in names):
            raise ValueError("required notice components are absent")
        expected = {"manifest.json"}
        for c in components:
            if not c["files"]:
                raise ValueError("component has no notices")
            for file in c["files"]:
                member = file["member"]
                if (not safe_path(file["path"]) or not TEXT_MEMBER.fullmatch(member) or
                    file["sha256"] != digest(entries[member]) or member != f"texts/{file['sha256']}.txt"):
                    raise ValueError("notice content or path mismatch")
                expected.add(member)
        if expected != entries.keys():
            raise ValueError("unreferenced notice files")
        runtime_files = {f["path"] for c in components if c["name"] == runtime for f in c["files"]}
        if kind == "core":
            required = {"COPYRIGHT-library.html"}
            if not any(p in runtime_files for p in ("licenses/MIT.txt", "LICENSE-MIT")) or not any(
                    p in runtime_files for p in ("licenses/Apache-2.0.txt", "LICENSE-APACHE")):
                raise ValueError("required Rust runtime license texts are absent")
            version = tomllib.loads((root / "vendor/csqtt/rust-client/Cargo.toml").read_text())["package"]["rust-version"]
            toolchain = "rustc " + version
        else:
            required = {"LICENSE", "PATENTS"}
            version = re.search(r"^go ([0-9.]+)$", (root / "go.mod").read_text(), re.M).group(1)
            toolchain = "go" + version
        if not required <= runtime_files or manifest["toolchain"] != toolchain:
            raise ValueError("required runtime notices/toolchain are absent")
    except (tarfile.TarError, EOFError, OSError, KeyError, TypeError, AttributeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid notice archive") from exc
    return entries


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("core", "manager"))
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target", help="same custom target JSON as the core build")
    parser.add_argument("--go", default="go", help="Go executable from the manager build")
    args = parser.parse_args()
    texts: dict[str, bytes] = {}
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if args.kind == "core":
        if not args.target:
            parser.error("core notices require the build --target")
        version = subprocess.check_output(["rustc", "--version"], text=True).split()[1]
        sysroot = Path(subprocess.check_output(["rustc", "--print", "sysroot"], text=True).strip())
        directory = sysroot / "share/doc/rust"
        files = [directory / "COPYRIGHT-library.html"]
        files += notice_files(directory / "licenses") if (directory / "licenses").is_dir() else []
        files += [p for p in (directory / "LICENSE-MIT", directory / "LICENSE-APACHE") if p.is_file()]
        if not any(p.name in ("MIT.txt", "LICENSE-MIT") for p in files) or not any(
                p.name in ("Apache-2.0.txt", "LICENSE-APACHE") for p in files):
            raise ValueError("Rust runtime license texts are missing")
        metadata = json.loads(subprocess.check_output([
            "cargo", "metadata", "--offline", "--locked", "--format-version=1",
            "--manifest-path", str(ROOT / "vendor/csqtt/rust-client/Cargo.toml"),
            "--filter-platform", args.target, "-Z", "json-target-spec"], text=True))
        lock = tomllib.loads((ROOT / "vendor/csqtt/rust-client/Cargo.lock").read_text())
        components = cargo_components(metadata, lock, ROOT, texts)
        components.append(component("rust-runtime", version, "https://www.rust-lang.org/", None, directory, files, texts))
        toolchain = "rustc " + version
    else:
        version = subprocess.check_output([args.go, "version", "-m", str(args.binary)], text=True).splitlines()[0].rsplit(": ", 1)[-1]
        directory = Path(subprocess.check_output([args.go, "env", "GOROOT"], text=True).strip())
        if (directory / "VERSION").read_text().splitlines()[0] != version:
            raise ValueError("Go source runtime differs from the built manager")
        files = [directory / "LICENSE", directory / "PATENTS"] + notice_files(directory / "src")
        components = [component("go-runtime", version, "https://go.dev/", "BSD-3-Clause", directory, files, texts)]
        toolchain = version
    data = bundle(args.kind, args.binary, toolchain, revision, components, texts)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(data)
    args.output.with_name(args.output.name + ".sha256").write_text(
        f"{digest(data)}  {args.output.name}\n", encoding="ascii")
    print(f"{args.output.name}: {digest(data)}")


if __name__ == "__main__":
    main()
