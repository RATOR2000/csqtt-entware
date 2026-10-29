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
- Ordinary application disconnect stopped both CSQTT and the userspace WG
  bridge. The phone retained its LAN panel access and a fresh external HTTPS
  request in a private tab failed. A previously displayed page was not counted
  as connectivity evidence. Reconnection then passed native DNS UDP/TCP and
  verified HTTPS with a distinct provider exit, without further phone actions.
- Normal candidate `0.1.0~dev6` installed and preserved settings/WG keys across
  the upgrade. Temporary CPU profiling uses private overlay builds only and is
  followed by reinstalling and hashing the normal disk and running executable.
- Installer now forces same-version payload reinstallation as well as upgrades,
  so repeating the future one-command installer repairs modified program files.
  Owner settings remain outside the payload and are backed up. Eleven host
  packaging/bootstrap tests and shell syntax checks passed after this change.
- Go/package CI 40714188038 passed at `45ecde8`. A real same-version reinstall
  then replaced the temporary profiling executable and preserved owner settings;
  hashes of both normal installed and running ELFs match the packaged builds.
- Full manager/bridge stop was tested automatically with native policy-marked
  sockets: WG DNS UDP/TCP and HTTPS failed, provider-policy HTTPS and native LAN
  management remained available. Startup restored the complete VPN path.
- A separately verified SIGTERM to the owned core triggered automatic recovery
  to nine channels and working native WG DNS/HTTPS. Device UUID, WG keys and
  settings stayed stable. The identity generation counter correctly advances
  on restart; it is not the persistent device identifier.
- Three concurrent bounded HTTPS downloads passed, followed by repeated
  three-stream bursts and panel/memory monitoring. All sampled panel requests
  completed and the available-memory acceptance margin was retained. This is
  a short synthetic load test on one physical LAN client, not three-device or
  extended-duration qualification. Exact captures and measurements stay private.
- Native SSH management authentication and commands, Entware SSH and web access
  were checked. Temporary compiler, tracer, packet-capture tools, preload shim
  and profiling executables were removed from the router after normal recovery.
- The owner explicitly authorized a router reboot and a bounded server-link
  fault. Both passed. A source-routing-aware blackhole test blocked only the
  core's public transport destinations, preserved provider-policy HTTPS, and
  automatically removed its own routes before VPN connectivity recovered.
  Injection must cover the native per-source table as well as main; derive the
  current table from rules rather than assuming main routes cover connected UDP.
- A changed boot ID confirmed a real reboot. Entware and the enabled client
  started automatically with nine channels; settings, UUID, WG interface and
  policy blocks were checked unchanged. Native management ports remained
  available; post-boot native WG DNS UDP/TCP and verified HTTPS passed.
- The owner can provide only one physical phone. Three concurrent streams and
  one real phone are verified; three physical clients must not be claimed as
  tested. Native SSH forwarding is available for USB-independent diagnostics.
- After separate owner authorization, the external EXT4 USB volume was safely
  disconnected through Keenetic and reconnected in software. A temporary static
  probe ran entirely in RAM with cached CA roots and was observed through native
  SSH forwarding: VPN HTTPS failed while provider HTTPS and native management
  remained available. Physical surprise removal was not performed or claimed.
- USB reattachment automatically restarted Entware/CSQTT with nine channels.
  Persistent settings, WG keys and UUID were verified unchanged; native WG DNS
  UDP/TCP and verified HTTPS passed again. The RAM probe was removed afterward.
- Dependency notices now cover the locked Rust crates, Rust and Go runtimes,
  manager dependencies and required PATENTS files. Packaging requires both
  binary-bound notice bundles and validates their files, hashes and locked
  inputs. The published-crate license gap has an exact upstream revision and
  checked-in supplement; SPDX labels alone are not used as license text.
- Core CI 40730577195 at `8a5fdb5` and Go/package CI 40731064893 at `37ae27f`
  passed. The final local preview candidate includes the full notices and was
  reinstalled on the router with owner settings and keys preserved. This is a
  private development candidate, not a published installable release.
- A three-stream HTTPS smoke test moved certificate verification and TLS onto
  the host while the temporary router relay retained the native VPN policy and
  CSQTT packet path. All three bounded transfers passed without retries, and
  the relay was removed. The saved report is one round, not the planned
  fifteen-minute monitored stability run. An earlier longer attempt containing
  a TLS reset remains a failed test and is not counted as acceptance.

## Restoration checkpoint

- After the development host's Windows reinstall, Git object verification,
  Go host tests/vet and Python packaging/bootstrap/notice tests passed again.
  The Windows-only symlink fixture is still skipped. Linux race/lifecycle and
  MIPS checks remain CI evidence, rather than new native-host checks.
- Restored artifact checksums and binary-bound notice inventories match. The
  private IPK is reproducible byte-for-byte from the restored binaries,
  notices and current packaging inputs. Installed router executables match
  these restored builds.
- Both router SSH services authenticated with the previously pinned host keys;
  web management and the private LAN panel tunnel work. The native WG loopback
  endpoint, MTU, WG-only policy and absence of a global IPv6 path were rechecked.
- Current authentication is waiting for a real VK CAPTCHA. Fresh native
  policy-routed DNS/HTTPS probes fail through VPN while provider HTTPS works.
  A local WG handshake is not being counted as Internet access. The owner must
  complete the real Helper flow before reconnect/load qualification can resume.
- The GitHub connector retains repository write access; terminal Git reads
  work, but its local credential-manager login was lost during the reinstall.
  No credentials or private restoration files are committed.

## Ownership and handoff

- Root: integration, router/UI checks and STATUS.
- Subagent build, manager review and packaging scopes completed. Recheck live
  agents before delegating further work; do not assume these sessions exist.

## Next

The installed candidate currently needs the owner's real VK CAPTCHA confirmation.
Verify the Helper flow and restored end-to-end traffic, then complete the monitored
stability run. Only one physical test device is available. Keep those limits
explicit before deciding the first preview's qualification scope. Prepare the
final versioned release and test its actual one-command download after its
acceptance gates pass. No public installable preview has been published.

