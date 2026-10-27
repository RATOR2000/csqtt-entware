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
- Go CI 40545782402 at `db70f79` also passed after extraction postconditions,
  private-directory ownership checks and the RAM runtime changes.
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
- Candidate `0.1.0~dev4` was installed/upgraded successfully with complete
  inventory/license verification. Settings and WG keys were checked unchanged
  byte-for-byte across the upgrade; native service and tmpfs runtime are live.
- Panel opened through an SSH tunnel. The user was asked to enter server data
  locally and connect a LAN test device; no production server data was supplied
  or inferred by the implementation agent.

## Ownership and handoff

- Root: integration, router/UI checks and STATUS.
- Subagent build, manager review and packaging scopes completed. Recheck live
  agents before delegating further work; do not assume these sessions exist.

## Next

The disposable fixture was removed and the original main routes restored.
Wait for the user to save server credentials and connect a LAN test device.
Then validate real CSQTT/VK authorization, generate/import the real profile,
check native policy/NAT/DNS, and measure memory and traffic. No real VPN path or
throughput has passed yet. Reboot, USB removal or disruptive WAN/server tests
require separate explicit authorization; do not run them now.
