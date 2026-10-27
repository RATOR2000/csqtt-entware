"""Host checks for IPK boundaries; these do not qualify router installation."""
import importlib.util
import io
from pathlib import Path
import struct
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

    def test_deterministic_ipk_and_safe_payload(self):
        first = package.build(self.core, self.manager, "0.1.0~dev1")
        self.assertEqual(first, package.build(self.core, self.manager, "0.1.0~dev1"))
        archive = members(first)
        self.assertEqual(set(archive), {"debian-binary", "control.tar.gz", "data.tar.gz"})
        self.assertEqual(archive["debian-binary"], b"2.0\n")
        with tarfile.open(fileobj=io.BytesIO(archive["data.tar.gz"])) as tar:
            names = tar.getnames()
            self.assertIn("opt/bin/csqtt-client", names)
            self.assertIn("opt/bin/csqtt-entware", names)
            self.assertEqual(tar.getmember("opt/etc/init.d/S90csqtt").mode, 0o755)
            self.assertFalse(any(name.startswith("opt/etc/csqtt/") for name in names))
            self.assertIn("opt/share/licenses/csqtt-entware/golang.zx2c4.com/wireguard/LICENSE", names)
            for item in tar.getmembers():
                self.assertTrue(item.isfile())
                self.assertFalse(item.name.startswith("/") or ".." in Path(item.name).parts)
                self.assertEqual((item.uid, item.gid, item.mtime), (0, 0, 0))
                self.assertLess(item.mode & 0o002, 1)

    def test_control_hooks_and_offline_install_boundary(self):
        archive = members(package.build(self.core, self.manager, "0.1.0~dev1"))
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
                package.build(self.core, self.manager, "0.1.0~dev1")
        data = elf(); data[5] = 2; self.core.write_bytes(data)
        with self.assertRaises(ValueError):
            package.build(self.core, self.manager, "0.1.0~dev1")

    def test_rejects_control_and_path_injection_in_version(self):
        for version in ("", "1\nArchitecture: all", "../../bad", "1/../../bad", "1;reboot"):
            with self.assertRaises(ValueError):
                package.build(self.core, self.manager, version)


if __name__ == "__main__":
    unittest.main()
