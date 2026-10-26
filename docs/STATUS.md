# Development status

Implementation started. This is not an installable or qualified release.

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
  by device identity. The daemon requires an explicit packet-backend extension.

## In progress

1. MIPS cross toolchain and crypto/core proof.
2. Bounded userspace WireGuard bridge and web manager.
3. Entware service, packaging, installer and real-device acceptance.

No MIPS build, native handshake or real VPN traffic is qualified yet.
