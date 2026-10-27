# Development status

Development candidate implemented and installed on the target. No public
installable preview or qualified VPN release has been published.

## Agreed behavior

- Separate public `RATOR2000/csqtt-entware`; OpenWrt repository is read-only.
- LAN web panel, default port 8080, no login; Origin/Host and CSRF protection.
- Native WireGuard profile feeds a local userspace WG-to-CSQTT packet bridge.
- Original CSQTT 2.1.9, stable identity; minimum nine transport connections.
- Native Keenetic policy selects devices; no WAN fallback; IPv4 first.
- User enters server credentials in the local panel for end-to-end validation.

## Evidence

- Read-only hardware exploration confirms MIPS soft-float Entware and a native
  WireGuard component. Network namespaces are unavailable on the target.
- Source analysis confirms raw-IP UDP adapter and persistent server allocation
  by device identity. The daemon now has the explicit managed packet backend.

## Implemented and checked

- Fixed, connected loopback raw-IP UDP daemon backend: no TUN or route hooks.
- Safe 64-bit atomics and Entware glibc 2.27 MIPS soft-float cross compilation.
- Core CI run 40373706420 at `2cf990df629cef8e6632b432cf4d09a65b756958`
  passed 381 host tests, ELF ABI checks, selected emulated MIPS tests and startup.
- Go manager, LAN UI, private settings, persistent WG keys, profile export,
  bounded packet bridge and integrated on-demand CAPTCHA helper broker exist.
- Go host tests, vet and MIPS cross compilation passed. Bridge tests include
  real encrypted round trips, UDP recovery, ICMP and fragment preservation.
- Go CI 40541973514 at `9a136f5932954c0fc04e525d5d90f806253884b1`
  passed Linux lifecycle/race/vet, packaging tests and MIPS manager compilation.
- Both executables passed native startup on the target. A disposable profile
  was imported through the stock UI with a loopback endpoint; the native WG
  client completed a handshake and round-tripped full 1280-byte ICMP packets.
- The stock 3.8 importer ignores MTU. UI and README now require setting 1280
  manually in the native connection's advanced settings, with TCP MSS enabled.
- Actual installer preflight and installation passed. The first development
  package exposed missing parent directories for licenses despite opkg exit 0;
  the corrected data archive includes directories and the installer verifies
  the entire installed inventory, executables and seven license files.
- Development upgrades preserve owner settings and WG keys. HTTP checks on the
  installed panel confirm Host/Origin/CSRF and secret-redaction behavior.
- Managed runtime is in private `/tmp/csqtt` (RAM); persistent settings/identity
  remain on USB. This avoids frequent synchronous status writes to the USB.

## Ownership and handoff

- Root: integration, router/UI checks and STATUS.
- Subagent build, manager review and packaging scopes completed. Recheck live
  agents before delegating further work; do not assume these sessions exist.

## Next

The disposable fixture was removed and the original main routes restored.
Finish the RAM-runtime candidate upgrade and source checkpoint, then ask the
user to enter server credentials in the panel and attach a LAN test device.
Real CSQTT/VK authorization, policy/NAT/DNS behavior, memory under real traffic,
throughput and outage tests are still pending. Reboot, USB removal or disruptive
WAN/server tests require separate explicit authorization; do not run them now.
