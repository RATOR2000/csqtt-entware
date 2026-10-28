"""Offline fixture checks for distributed notices and untrusted bundle inputs."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("notices", ROOT / "scripts/notices.py")
notices = importlib.util.module_from_spec(spec)
spec.loader.exec_module(notices)
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


def archive(entries):
    """Build adversarial archives without invoking the collector's writer."""
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.USTAR_FORMAT) as tar:
        for name, data, kind in entries:
            item = tarfile.TarInfo(name)
            item.type = kind
            item.size = len(data) if kind == tarfile.REGTYPE else 0
            item.linkname = "manifest.json" if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE) else ""
            tar.addfile(item, io.BytesIO(data) if item.isfile() else None)
    return output.getvalue()


def unpack(data):
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        return {item.name: tar.extractfile(item).read() for item in tar}


class NoticeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "repo"
        self.root.mkdir()
        self.write("vendor/csqtt/LICENSE", "Original CSQTT authors and license\n")
        self.write("vendor/csqtt/rust-client/Cargo.toml", '[package]\nrust-version = "1.97.1"\n')
        self.write("vendor/csqtt/rust-client/Cargo.lock", "# locked fixture\n")
        self.write("vendor/csqtt/rust-client/vendor/primp/Cargo.toml", '[package]\nname = "primp"\n')
        self.write("vendor/csqtt/rust-client/vendor/primp/LICENSE-MIT", "Primp upstream notice\n")
        self.write("go.mod", "module example.test/fixture\n\ngo 1.26.8\n")
        self.write("go.sum", "fixture checksum\n")
        self.write("vendor/modules.txt", "# fixture v1.0.0\n")
        self.binary = self.write("build/client", b"fixture executable bytes")
        self.aws = self.root / "registry/aws-lc-sys-0.44.0"
        self.write("registry/aws-lc-sys-0.44.0/Cargo.toml", "# fixture crate\n")
        self.write("registry/aws-lc-sys-0.44.0/aws-lc/third_party/fiat/LICENSE", "Fiat upstream notice\n")
        self.write("registry/aws-lc-sys-0.44.0/aws-lc/NOTICE", "AWS upstream notice\n")
        self.write("registry/aws-lc-sys-0.44.0/source.c", "not a notice")
        self.custom = self.root / "registry/custom-1.0.0"
        self.write("registry/custom-1.0.0/Cargo.toml", "# custom license-file fixture\n")
        self.write("registry/custom-1.0.0/legal/terms.txt", "Custom upstream terms\n")
        self.metadata = {"resolve": {"nodes": [{"id": x} for x in ("app", "aws", "custom")]},
                         "packages": [
                             self.package("app", "csqtt-client", "2.1.9", None,
                                          self.root / "vendor/csqtt/rust-client"),
                             self.package("aws", "aws-lc-sys", "0.44.0", REGISTRY, self.aws),
                             self.package("custom", "custom", "1.0.0", REGISTRY, self.custom,
                                          license_file="legal/terms.txt"),
                             self.package("unused", "unused", "9.0.0", REGISTRY,
                                          self.root / "does-not-exist"),
                         ]}
        self.lock = {"package": [
            {"name": "csqtt-client", "version": "2.1.9"},
            {"name": "aws-lc-sys", "version": "0.44.0", "source": REGISTRY, "checksum": "a" * 64},
            {"name": "custom", "version": "1.0.0", "source": REGISTRY, "checksum": "b" * 64},
        ]}
        self.runtime = self.root / "runtime"
        self.write("runtime/COPYRIGHT-library.html", "Rust library contributor notices\n")
        self.write("runtime/licenses/MIT.txt", "Rust MIT terms\n")
        self.write("runtime/licenses/Apache-2.0.txt", "Rust Apache terms\n")

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data.encode() if isinstance(data, str) else data)
        return path

    @staticmethod
    def package(identifier, name, version, source, directory, **fields):
        return {"id": identifier, "name": name, "version": version, "source": source,
                "manifest_path": str(directory / "Cargo.toml"), "license": "fixture", **fields}

    def core_bundle(self):
        texts = {}
        components = notices.cargo_components(self.metadata, self.lock, self.root, texts)
        runtime_files = [self.runtime / "COPYRIGHT-library.html", self.runtime / "licenses/MIT.txt",
                         self.runtime / "licenses/Apache-2.0.txt"]
        components.append(notices.component("rust-runtime", "1.97.1", "https://www.rust-lang.org/",
                                            None, self.runtime, runtime_files, texts))
        return notices.bundle("core", self.binary, "rustc 1.97.1", "1" * 40,
                              components, texts, self.root)

    def mutated(self, change):
        entries = unpack(self.core_bundle())
        manifest = json.loads(entries["manifest.json"])
        change(manifest)
        entries["manifest.json"] = json.dumps(manifest).encode()
        return archive([(name, data, tarfile.REGTYPE) for name, data in entries.items()])

    def verify(self, data):
        return notices.verify(data, "core", self.binary.read_bytes(), self.root)

    def test_locked_graph_preserves_nested_and_custom_notices(self):
        texts = {}
        components = notices.cargo_components(self.metadata, self.lock, self.root, texts)
        self.assertEqual([c["name"] for c in components], ["aws-lc-sys", "csqtt-client", "custom"])
        aws, app, custom = components
        self.assertEqual({f["path"] for f in aws["files"]},
                         {"aws-lc/NOTICE", "aws-lc/third_party/fiat/LICENSE"})
        self.assertEqual(aws["crate_sha256"], "a" * 64)
        self.assertEqual([f["path"] for f in custom["files"]], ["legal/terms.txt"])
        self.assertEqual([f["path"] for f in app["files"]], ["LICENSE"])
        self.assertEqual(texts[app["files"][0]["member"]], b"Original CSQTT authors and license\n")

    def test_rejects_incomplete_or_unlocked_cargo_graph(self):
        for change in (lambda metadata, lock: metadata["resolve"]["nodes"].append({"id": "missing"}),
                       lambda metadata, lock: lock["package"].pop(),
                       lambda metadata, lock: lock["package"][1].pop("checksum")):
            metadata, lock = copy.deepcopy(self.metadata), copy.deepcopy(self.lock)
            change(metadata, lock)
            with self.assertRaises(ValueError):
                notices.cargo_components(metadata, lock, self.root, {})

    def test_missing_notices_fail_instead_of_skipping_component(self):
        for path in notices.notice_files(self.aws):
            path.unlink()
        with self.assertRaisesRegex(ValueError, "missing notice"):
            notices.cargo_components(self.metadata, self.lock, self.root, {})

    def test_supplement_requires_exact_locked_identity_and_verbatim_upstream_bytes(self):
        for path in notices.notice_files(self.aws):
            path.unlink()
        raw = b"Fixture upstream copyright and permission notice.\n"
        path = "packaging/notices/fixture/LICENSE"
        supplement = self.write(path, raw)
        origin = "https://example.test/upstream/0123456789abcdef/LICENSE"
        expected = notices.digest(raw)
        mapping = {("aws-lc-sys", "0.44.0", "a" * 64): (path, expected, origin)}
        with patch.object(notices, "CARGO_SUPPLEMENTS", mapping):
            entries = unpack(self.core_bundle())
            manifest = json.loads(entries["manifest.json"])
            aws = next(c for c in manifest["components"] if c["name"] == "aws-lc-sys")
            self.assertEqual(aws["files"], [{"path": "LICENSE", "member": f"texts/{expected}.txt",
                                             "sha256": expected, "origin": origin}])
            self.assertEqual(entries[aws["files"][0]["member"]], raw)
            self.assertEqual(manifest["inputs"][path], expected)
            serialized = entries["manifest.json"].decode().replace("\\\\", "\\")
            self.assertNotIn(str(self.root), serialized)
            self.assertNotIn(self.root.as_posix(), serialized)
            for field, wrong in (("name", "different-crate"), ("version", "0.44.1"),
                                 ("checksum", "c" * 64)):
                with self.subTest(field=field):
                    metadata, lock = copy.deepcopy(self.metadata), copy.deepcopy(self.lock)
                    lock["package"][1][field] = wrong
                    if field != "checksum":
                        metadata["packages"][1][field] = wrong
                    with self.assertRaisesRegex(ValueError, "missing notice"):
                        notices.cargo_components(metadata, lock, self.root, {})
            supplement.write_bytes(raw + b"changed")
            with self.assertRaisesRegex(ValueError, "supplemental upstream notice hash mismatch"):
                notices.cargo_components(self.metadata, self.lock, self.root, {})

    def test_license_file_rejects_unsafe_relative_paths(self):
        for path in ("../LICENSE", "/LICENSE", "legal//terms.txt", "./LICENSE", "C:/LICENSE", "legal\\terms.txt"):
            with self.subTest(path=path):
                metadata = copy.deepcopy(self.metadata)
                metadata["packages"][2]["license_file"] = path
                with self.assertRaises(ValueError):
                    notices.cargo_components(metadata, self.lock, self.root, {})

    def test_license_directory_keeps_named_spdx_texts(self):
        self.assertEqual({p.name for p in notices.notice_files(self.runtime / "licenses")},
                         {"MIT.txt", "Apache-2.0.txt"})

    def test_source_symlinks_are_rejected(self):
        link = self.aws / "linked-legal"
        try:
            link.symlink_to(self.custom, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("host cannot create fixture symlinks")
        with self.assertRaisesRegex(ValueError, "symlink"):
            notices.notice_files(self.aws)
        with self.assertRaises(ValueError):
            notices.notice_files(link)

    def test_empty_and_oversized_source_notice_fail(self):
        path = self.write("runtime/NOTICE", b"")
        with self.assertRaises(ValueError):
            notices.component("fixture", "1", "fixture", None, self.runtime, [path], {})
        path.write_bytes(b"x" * 129)
        with patch.object(notices, "MAX_FILE", 128), self.assertRaises(ValueError):
            notices.component("fixture", "1", "fixture", None, self.runtime, [path], {})

    def test_bundle_is_deterministic_and_bound_to_binary_and_locked_inputs(self):
        data = self.core_bundle()
        self.assertEqual(data, self.core_bundle())
        self.verify(data)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            for item in tar:
                self.assertTrue(item.isfile())
                self.assertEqual((item.uid, item.gid, item.mtime, item.mode), (0, 0, 0, 0o644))
        with self.assertRaises(ValueError):
            notices.verify(data, "core", b"different executable", self.root)
        self.write("vendor/csqtt/rust-client/Cargo.lock", "# changed lockfile\n")
        with self.assertRaises(ValueError):
            self.verify(data)

    def test_bundle_runtime_and_revision_requirements(self):
        for change in (lambda m: m.update(source_revision="not-a-revision"),
                       lambda m: m.update(toolchain="rustc 1.0.0"),
                       lambda m: m.update(kind="manager"),
                       lambda m: m.update(components=[c for c in m["components"] if c["name"] != "rust-runtime"]),
                       lambda m: m["components"][-1]["files"].pop()):
            with self.assertRaises(ValueError):
                self.verify(self.mutated(change))

    def test_archive_rejects_traversal_duplicates_and_nonfiles(self):
        valid = unpack(self.core_bundle())
        entries = [(name, data, tarfile.REGTYPE) for name, data in valid.items()]
        attacks = [[(name, b"unsafe", tarfile.REGTYPE)] for name in
                   ("../outside", "/outside", "texts/../outside", "texts\\outside")]
        attacks += [entries + [entries[0]]]
        attacks += [[("manifest.json", b"", kind)] for kind in
                    (tarfile.DIRTYPE, tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE)]
        for attack in attacks:
            with self.subTest(attack=attack[0][0], kind=attack[0][2]):
                with self.assertRaises(ValueError):
                    self.verify(archive(attack))

    def test_archive_checks_content_hash_paths_and_exact_inventory(self):
        entries = unpack(self.core_bundle())
        member = next(name for name in entries if name.startswith("texts/"))
        entries[member] += b"tampered"
        with self.assertRaises(ValueError):
            self.verify(archive([(name, data, tarfile.REGTYPE) for name, data in entries.items()]))
        with self.assertRaises(ValueError):
            self.verify(self.mutated(lambda m: m["components"][0]["files"][0].update(path="../LICENSE")))
        entries = unpack(self.core_bundle())
        extra = b"unreferenced notice"
        entries[f"texts/{notices.digest(extra)}.txt"] = extra
        with self.assertRaisesRegex(ValueError, "unreferenced"):
            self.verify(archive([(name, data, tarfile.REGTYPE) for name, data in entries.items()]))

    def test_archive_limits_cover_files_count_expansion_and_compressed_input(self):
        text = b"x" * 4096
        member = f"texts/{notices.digest(text)}.txt"
        oversized = archive([(member, text, tarfile.REGTYPE)])
        with patch.object(notices, "MAX_FILE", 4095), self.assertRaises(ValueError):
            self.verify(oversized)
        with patch.object(notices, "MAX_TOTAL", 2048), self.assertRaisesRegex(ValueError, "expands"):
            self.verify(oversized)
        valid = self.core_bundle()
        with patch.object(notices, "MAX_FILES", 1), self.assertRaises(ValueError):
            self.verify(valid)
        with patch.object(notices, "MAX_TOTAL", len(valid) - 1), self.assertRaisesRegex(ValueError, "archive is too large"):
            self.verify(valid)
        with self.assertRaises(ValueError):
            self.verify(valid[:40])

    def test_go_runtime_requires_both_license_and_patents(self):
        directory = self.root / "go-runtime"
        files = [self.write("go-runtime/LICENSE", "Go upstream BSD notice\n"),
                 self.write("go-runtime/PATENTS", "Go upstream patent grant\n")]
        texts = {}
        components = [notices.component("go-runtime", "go1.26.8", "https://go.dev/", "BSD-3-Clause",
                                        directory, files, texts)]
        data = notices.bundle("manager", self.binary, "go1.26.8", "1" * 40, components, texts, self.root)
        notices.verify(data, "manager", self.binary.read_bytes(), self.root)
        components[0]["files"].pop()
        with self.assertRaises(ValueError):
            notices.bundle("manager", self.binary, "go1.26.8", "1" * 40, components, texts, self.root)


if __name__ == "__main__":
    unittest.main()
