"""Offline bootstrap boundaries; these tests never install or access a router."""
import hashlib
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "scripts/bootstrap.sh").read_text().rsplit('\nbootstrap_main "$@"', 1)[0]


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        if os.name == "nt":
            git = shutil.which("git")
            self.shell = Path(git).resolve().parents[1] / "bin/bash.exe" if git else None
        else:
            self.shell = shutil.which("sh")
        if not self.shell or not Path(self.shell).is_file():
            self.skipTest("POSIX shell unavailable")
        (ROOT / ".work").mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT / ".work")
        self.addCleanup(self.tmp.cleanup)
        self.stage = Path(self.tmp.name)

    def run_shell(self, command, **env):
        return subprocess.run([str(self.shell), "-c", SOURCE + "\n" + command],
                              capture_output=True, text=True, env={**os.environ, **env})

    def test_tag_parser_is_explicit_and_bounded(self):
        for tag in ("v1.2.3", "v0.1.0-preview.1", "v0.1.0~dev4"):
            result = self.run_shell("validate_tag " + shlex.quote(tag))
            self.assertEqual(result.returncode, 0, result.stderr)
        for tag in ("", "latest", "main", "vlatest", "1.2.3", "v1/../main",
                    "v1;reboot", "v1\nmain", "v" + "1" * 65):
            result = self.run_shell("bootstrap_main " + shlex.quote(tag))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("explicit", result.stderr)

    def test_checksums_verify_both_payload_types_and_reject_tampering(self):
        for name in ("install.sh", "csqtt-entware_1.2.3_mipsel-3.4.ipk"):
            payload = self.stage / name
            checksum = self.stage / (name + ".sha256")
            payload.write_bytes(b"trusted offline fixture\n")
            digest = hashlib.sha256(payload.read_bytes()).hexdigest()
            checksum.write_text(f"{digest}  {name}\n", newline="\n")
            command = "verify_checksum " + " ".join(map(shlex.quote, (payload.as_posix(), checksum.as_posix(), name)))
            self.assertEqual(self.run_shell(command).returncode, 0)
            payload.write_bytes(b"changed private test data\n")
            result = self.run_shell(command)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("SHA256 mismatch", result.stderr)
            self.assertNotIn("private test data", result.stderr)

    def test_checksum_parser_rejects_wrong_names_extra_records_and_commands(self):
        payload = self.stage / "install.sh"
        payload.write_bytes(b"fixture")
        digest = hashlib.sha256(payload.read_bytes()).hexdigest()
        checksum = self.stage / "install.sh.sha256"
        command = "verify_checksum " + " ".join(map(shlex.quote, (payload.as_posix(), checksum.as_posix(), "install.sh")))
        for text in (digest, f"{digest}  ../install.sh\n", f"{digest}  install.sh\n" * 2,
                     f"{digest}  install.sh extra\n", f"{digest}  install.sh;reboot\n",
                     f"{'x' * 64}  install.sh\n", f"{digest}  install\r.sh\n"):
            checksum.write_text(text, newline="\n")
            with self.subTest(text=text):
                self.assertNotEqual(self.run_shell(command).returncode, 0)

    def test_fetch_validates_redirects_and_never_enables_insecure_tls(self):
        wget = self.stage / "wget"
        calls = self.stage / "calls"
        wget.write_text("""#!/bin/sh
destination= url=
for arg do
    case "$arg" in --output-document=*) destination=${arg#*=} ;; https://*) url=$arg ;; esac
done
printf '%s\\n' "$@" >> "$MOCK_CALLS"
case "$url" in
    https://github.com/*)
        printf '  HTTP/1.1 302 Found\\n  Location: %s\\n' "$MOCK_LOCATION" >&2
        printf 'Location: %s [following]\\n' "$MOCK_LOCATION" >&2
        exit 8 ;;
    https://release-assets.githubusercontent.com/*)
        printf 'offline fixture' > "$destination" ;;
    *) exit 1 ;;
esac
""", newline="\n")
        wget.chmod(0o700)
        setup = "\n".join(("stage=" + shlex.quote(self.stage.as_posix()),
                           "wget_bin=" + shlex.quote(wget.as_posix()), "ca_bundle=/test-ca.crt",
                           'fetch_release https://github.com/RATOR2000/csqtt-entware/releases/download/v1.2.3/install.sh "$stage/result" 128'))
        if os.name == "nt":
            # Git Bash cannot enforce POSIX file-size limits. Keep production's
            # fail-closed limit setup, and mock only this OS operation here.
            setup = "ulimit() { :; }\n" + setup
        good = "https://release-assets.githubusercontent.com/github-production-release-asset/1/fixture?token=public"
        result = self.run_shell(setup, MOCK_CALLS=calls.as_posix(), MOCK_LOCATION=good)
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = calls.read_text()
        for flag in ("--no-config", "--check-certificate", "--max-redirect=0", "--ca-certificate=/test-ca.crt"):
            self.assertIn(flag, arguments)
        self.assertNotIn("--no-check-certificate", arguments)
        for location in ("http://release-assets.githubusercontent.com/file", "https://example.invalid/file",
                         "https://release-assets.githubusercontent.com.evil.invalid/file", good + "\rbad"):
            calls.write_text("")
            result = self.run_shell(setup, MOCK_CALLS=calls.as_posix(), MOCK_LOCATION=location)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(calls.read_text().count("--output-document="), 1)
            self.assertNotIn(location, result.stderr)


if __name__ == "__main__":
    unittest.main()
