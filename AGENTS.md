# CSQTT Entware

Develop only this repository. `RATOR2000/csqtt-openwrt` is a read-only source:
never push, edit, open a PR, or change its settings.

Read `docs/STATUS.md` before continuing. Preserve original CSQTT 2.1.9 protocol,
identity, license and attribution. Target KN-1710, KeeneticOS 3.8.7, Entware
MIPS32r2 little-endian soft-float, glibc 2.27, 128 MB RAM.

Native Keenetic WireGuard connects to a local userspace packet bridge. Its
native policy is the only device selector. The policy must have no WAN backup.
Never claim a WireGuard handshake proves end-to-end CSQTT connectivity.

No passwords or VK links in command arguments, Git, logs, public diagnostics or
status responses. Keep private router captures and build outputs in `.work/`.
Do not commit personal host addresses, hardware identifiers or measurements.

User authorized implementation and installation on the supplied test Keenetic.
Do not reboot, unplug USB, interrupt the upstream router or run destructive
fault tests without explicit authorization for those actions. Preserve access.

Keep STATUS current, save checkpoint commits and distinguish code, host tests,
cross compilation, router smoke checks and real CSQTT traffic validation.
Do not publish installable preview releases before the documented gates pass.
