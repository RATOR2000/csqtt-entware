"""Host checks for IPK boundaries; these do not qualify router installation."""
import importlib.util
import io
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import tempfile
import tarfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("package", ROOT / "scripts/package.py")
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


def elf(machine=8, isa=0x70001000):
    result = bytearray(64)
    result[:7] = b"\x7fELF\x01\x01\x01"
    struct.pack_into("<HH", result, 16, 2, machine)
    struct.pack_into("<I", result, 36, isa)
    return result


def members(data):
    assert data[:2] == b"\x1f\x8b"
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        assert tar.getnames() == ["./debian-binary", "./control.tar.gz", "./data.tar.gz"]
        assert all(item.isfile() and item.mode == 0o644 for item in tar.getmembers())
        return {item.name.removeprefix("./"): tar.extractfile(item).read() for item in tar.getmembers()}


class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.core = Path(self.tmp.name) / "csqtt-client"
        self.manager = Path(self.tmp.name) / "csqtt-entware"
        self.core.write_bytes(elf())
        self.manager.write_bytes(elf(isa=0x50001000))
        self.notice_bundles = []
        for kind, binary, toolchain, filenames in (
                ("core", self.core, "rustc 1.97.1", ("COPYRIGHT-library.html", "LICENSE-MIT", "LICENSE-APACHE")),
                ("manager", self.manager, "go1.26.8", ("LICENSE", "PATENTS"))):
            directory = Path(self.tmp.name) / kind
            directory.mkdir()
            for name in filenames:
                (directory / name).write_text("fixture " + name)
            texts = {}
            runtime = "rust-runtime" if kind == "core" else "go-runtime"
            components = [package.notices.component(runtime, "fixture", "fixture", None,
                          directory, list(directory.iterdir()), texts)]
            if kind == "core":
                components += [package.notices.component("csqtt-client", "2.1.9", "fixture", None,
                               ROOT, [ROOT / "LICENSE"], texts)]
            bundle = Path(self.tmp.name) / (kind + "-notices.tar.gz")
            bundle.write_bytes(package.notices.bundle(kind, binary, toolchain, "0" * 40, components, texts))
            self.notice_bundles.append(bundle)

    def build(self, version):
        return package.build(self.core, self.manager, version, *self.notice_bundles)

    def test_deterministic_ipk_and_safe_payload(self):
        first = self.build("0.1.0~dev1")
        self.assertEqual(first, self.build("0.1.0~dev1"))
        archive = members(first)
        self.assertEqual(set(archive), {"debian-binary", "control.tar.gz", "data.tar.gz"})
        self.assertEqual(archive["debian-binary"], b"2.0\n")
        with tarfile.open(fileobj=io.BytesIO(archive["data.tar.gz"])) as tar:
            names = tar.getnames()
            self.assertIn("opt/bin/csqtt-client", names)
            self.assertIn("opt/bin/csqtt-entware", names)
            self.assertEqual(tar.getmember("opt/etc/init.d/S90csqtt").mode, 0o755)
            self.assertFalse(any(name == "opt/etc/csqtt" or name.startswith("opt/etc/csqtt/") for name in names))
            self.assertIn("opt/share/licenses/csqtt-entware/golang.zx2c4.com/wireguard/LICENSE", names)
            self.assertIn("opt/share/licenses/csqtt-entware/golang.org/x/crypto/PATENTS", names)
            self.assertIn("opt/share/licenses/csqtt-entware/core-notices/manifest.json", names)
            self.assertIn("opt/share/licenses/csqtt-entware/manager-notices/manifest.json", names)
            for item in tar.getmembers():
                self.assertTrue(item.isfile() or item.isdir())
                if item.isdir():
                    self.assertEqual(item.mode, 0o755)
                self.assertFalse(item.name.startswith("/") or ".." in Path(item.name).parts)
                self.assertEqual((item.uid, item.gid, item.mtime), (0, 0, 0))
                self.assertLess(item.mode & 0o002, 1)

    def test_payload_directories_precede_every_file_parent(self):
        archive = members(self.build("0.1.0~dev2"))
        with tarfile.open(fileobj=io.BytesIO(archive["data.tar.gz"])) as tar:
            seen = set()
            for item in tar.getmembers():
                for parent in Path(item.name).parents:
                    if str(parent) != ".":
                        self.assertIn(parent.as_posix(), seen, f"missing prior directory for {item.name}")
                if item.isdir():
                    seen.add(item.name.rstrip("/"))
            self.assertIn("opt/share/licenses/csqtt-entware/golang.org/x/crypto", seen)
            self.assertIn("opt/share/licenses/csqtt-entware/golang.zx2c4.com/wireguard", seen)
        # No parent entries are added to the IPK's three-member outer archive
        # or to control.tar.gz.
        with tarfile.open(fileobj=io.BytesIO(archive["control.tar.gz"])) as tar:
            self.assertTrue(all(item.isfile() for item in tar.getmembers()))

    def test_control_hooks_and_offline_install_boundary(self):
        archive = members(self.build("0.1.0~dev1"))
        with tarfile.open(fileobj=io.BytesIO(archive["control.tar.gz"])) as tar:
            control = tar.extractfile("control").read().decode()
            self.assertIn("Architecture: mipsel-3.4\n", control)
            self.assertIn("Depends: libc (>= 2.27)", control)
            with tarfile.open(fileobj=io.BytesIO(archive["data.tar.gz"])) as payload:
                installed_size = sum(item.size for item in payload.getmembers())
            self.assertIn(f"Installed-Size: {installed_size}\n", control)
            for name in ("preinst", "postinst", "prerm", "postrm"):
                self.assertEqual(tar.getmember(name).mode, 0o755)
                data = tar.extractfile(name).read().decode()
                self.assertNotIn("killall", data)
                self.assertNotIn("ndmc -c", data)

    def test_service_tracks_real_executable_and_bounded_shutdown(self):
        service = (ROOT / "packaging/S90csqtt").read_text()
        self.assertIn('DAEMON_REAL=$(readlink -f "$DAEMON"', service)
        self.assertIn('= "$DAEMON_REAL"', service)
        self.assertIn('remaining=20', service)
        self.assertNotIn('killall', service)
        self.assertIn('>/dev/null 2>&1', service)

    def test_rejects_wrong_or_truncated_executable(self):
        for data in (b"", elf(machine=62), elf(isa=0x60001000), b"MZ" + bytes(100)):
            self.core.write_bytes(data)
            with self.assertRaises(ValueError):
                self.build("0.1.0~dev1")
        data = elf(); data[5] = 2; self.core.write_bytes(data)
        with self.assertRaises(ValueError):
            self.build("0.1.0~dev1")

    def test_rejects_control_and_path_injection_in_version(self):
        for version in ("", "1\nArchitecture: all", "../../bad", "1/../../bad", "1;reboot"):
            with self.assertRaises(ValueError):
                self.build(version)

    def test_rejects_missing_notices_for_preview(self):
        self.notice_bundles[0].unlink()
        with self.assertRaises(FileNotFoundError):
            self.build("0.1.0~preview.1")

    def test_rejects_notices_from_another_binary(self):
        self.manager.write_bytes(elf(isa=0x50001000) + b"changed")
        with self.assertRaisesRegex(ValueError, "provenance"):
            self.build("0.1.0~preview.1")

    def test_installer_postcondition_detects_partial_extraction(self):
        if os.name == "nt":
            git = shutil.which("git")
            shell = Path(git).resolve().parents[1] / "bin/bash.exe" if git else None
            if shell is None or not shell.is_file():
                self.skipTest("Git Bash is needed for shell postcondition tests on Windows")
            shell = str(shell)
        else:
            shell = shutil.which("sh")
            if shell is None:
                self.skipTest("POSIX sh is unavailable")
        script = (ROOT / "scripts/install.sh").read_text()
        function = re.search(r"^verify_payload\(\) \{\n.*?^\}", script, re.M | re.S).group(0)
        manifest = members(self.build("0.1.0~dev2"))
        root = Path(self.tmp.name) / "installed"
        paths = []
        with tarfile.open(fileobj=io.BytesIO(manifest["data.tar.gz"])) as payload:
            for item in payload.getmembers():
                destination = root / item.name
                paths.append("/" + item.name.rstrip("/"))
                if item.isdir():
                    destination.mkdir(parents=True, exist_ok=True)
                else:
                    destination.write_bytes(payload.extractfile(item).read())
                    if item.name in ("opt/bin/csqtt-client", "opt/bin/csqtt-entware"):
                        # Git Bash's -x recognizes executable file formats on
                        # Windows; a cross-target ELF cannot be executable by
                        # this host. Only presence/mode is under test here.
                        destination.write_bytes(b"#!/bin/sh\nexit 0\n")
                    destination.chmod(item.mode)
        inventory = Path(self.tmp.name) / "inventory.txt"

        def verify(entries):
            inventory.write_text("Package csqtt-entware is installed on root and has following files:\n" + "\n".join(entries) + "\n", newline="\n")
            command = ("opkg() { cat " + shlex.quote(inventory.as_posix()) + "; }\n" +
                       function + "\nverify_payload " + shlex.quote(root.as_posix()))
            return subprocess.run([shell, "-c", command], capture_output=True, text=True).returncode

        self.assertEqual(verify(paths), 0)
        missing = root / "opt/share/licenses/csqtt-entware/golang.zx2c4.com/wireguard/LICENSE"
        missing.unlink()
        self.assertNotEqual(verify(paths), 0, "opkg exit 0 must not mask missing nested licenses")
        missing.write_text("restored test license")
        self.assertNotEqual(verify(paths + ["/etc/shadow"]), 0, "manifest must remain inside /opt")
        self.assertNotEqual(verify(paths + ["/opt/../etc/shadow"]), 0, "manifest traversal must be rejected")
        self.assertNotEqual(verify([]), 0, "an empty opkg file inventory is not installation proof")


if __name__ == "__main__":
    unittest.main()
