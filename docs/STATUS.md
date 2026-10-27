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
- Candidate `0.1.0~dev5` was installed/upgraded successfully with complete
  inventory/license verification. Settings and WG keys were checked unchanged
  byte-for-byte across the upgrade; native service and tmpfs runtime are live.
- Panel opened through an SSH tunnel; the owner entered credentials locally.
- Native startup exposed an Entware libc `getrandom` stub returning ENOSYS.
  `31c9293` calls the kernel CSPRNG on Linux MIPS GNU; it does not substitute a
  weak entropy source. Core CI 40599225139 passed, including fresh entropy,
  UUID generation and identity persistence. The installed production ELF now
  authenticates without the temporary diagnostic preload.
- Go CI 40599356532 passed for `aeed323`: bounded, allowlisted startup errors
  and a retry action after a stopped connection, without exposing raw stderr.
- Real VK authorization, nine CSQTT transport connections and a validated UDP
  DNS response have passed on the router. The real native WG profile connects
  to loopback; its actual MTU was corrected and verified as 1280, with MSS on.
- One owner-supplied LAN phone is assigned to the WG-only CSQTT policy. Native
  conntrack confirms its public TCP/UDP flows are NATed into the CSQTT address;
  the owner also confirmed browsing and the VPN server's external exit address.
- Policy-routed native tests passed DNS over UDP/TCP and certificate-verified
  HTTPS. The provider and VPN exit addresses differ. A unique DNS lookup from
  the phone was captured through the WG-bound resolver without a matching WAN
  query. Private captures and exact measurements remain outside Git.
- Short native transfer/resource checks passed without memory pressure. They
  show a CPU bottleneck and do not establish three-device or sustained-load
  acceptance. A private, temporary CPU profiling build is prepared to locate
  the cost before considering changes; it adds no public diagnostic endpoint.
- The WG DNS is interface-specific; no global Any DNS, DoH/DoT or filtering
  override was found. No global IPv6 address or IPv6 route is currently active.
- KeeneticOS 3.8 keeps every connection in its immutable built-in Default
  policy. Therefore Home and Guest were assigned to a separate ISP policy
  containing existing provider connections and explicitly excluding WG. The
  Default policy is unused; the phone retains its explicit CSQTT assignment.
- Explicit-tag bootstrap, checksum/redirect validation, four offline tests and
  native staging limits passed at `0e77a03`. No release URL is published yet.
- Go/package CI 40601885309 passed at `3ad639d`, including the corrected panel
  policy instructions. These sources are fast-forwarded to the new repo's main.

## Ownership and handoff

- Root: integration, router/UI checks and STATUS.
- Subagent build, manager review and packaging scopes completed. Recheck live
  agents before delegating further work; do not assume these sessions exist.

## Next

Complete the active ordinary application stop/recovery check with the phone,
inspect the private CPU profile, then install the normal candidate and check
recovery/profile identity. A single connected phone does not prove three-device
acceptance. Real
CAPTCHA and extended stability remain unverified. Reboot, USB removal and
disruptive WAN/server tests require separate explicit authorization; do not run
them now. No public installable preview is qualified by the evidence above.
