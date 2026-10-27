# Local WireGuard packet bridge

This package uses a custom `tun.Device` whose packets are fixed-endpoint IPv4
UDP datagrams, and a custom WireGuard `conn.Bind` that binds only IPv4 loopback.
Both report `BatchSize() == 1`. There is no kernel server TUN, TCP stack,
network namespace, packet rewriting or DNS forwarder. The sole peer's permitted
source and destination is the IPv4 address actually assigned by CSQTT. The
native Keenetic connection performs its ordinary client NAT before encryption.

The WireGuard implementation is pinned to upstream commit
`b3bc704ef0ee21a36298601a9e1e5ff90377ac52` (module version
`v0.0.0-20261024220952-b3bc704ef0ee`). Its MIT notices and license are preserved
under `vendor/golang.zx2c4.com/wireguard`.

The vendored changes are limited to `device/device.go` (one worker of each kind)
and the four platform `device/queueconstants_*.go` files (64 slots per queue,
2048 bytes per message buffer, 512 checked-out objects per pool). Do not run
`go mod vendor` directly: it would erase the separately maintained Rust core
under `vendor/csqtt` and also lose these bounded-memory patches. Stage the
generated Go vendor tree separately, merge it, and reapply/review these patches.

The five WireGuard wait pools share no backing allocations; each has a
512-object checkout limit. The message-buffer pool therefore retains at most
1 MiB of simultaneously checked-out packet data. For this one-peer, one-batch,
one-worker integration, the queues that can retain distinct packet buffers are
the peer staged queue (64), peer outbound queue (64), peer inbound queue (64),
global encryption queue (64), global decryption queue (64), and handshake queue
(64), with at most a handful in readers/workers/keepalive creation. Even this
deliberately overcounted bound is below 512, so producers cannot exhaust the
shared message pool while consumers wait for a buffer needed to drain it.
Container and element pools have the same limit. The adapter adds no packet
queue; each local UDP socket requests 64 KiB receive/send buffers. The profile
is asserted by tests, with staged-queue flood and shutdown tests.

The Go garbage collector can discard cached pool entries; this limit bounds
outstanding pool demand, not total process RSS. Runtime stacks, code pages,
crypto state, HTTP manager and OS socket memory require additional headroom.
Measure RSS and CPU on the target device before qualifying a release.

`ProbeDNS` sends one random DNS question as a raw IPv4/UDP packet through the
same CSQTT endpoint. Its one pending channel is bounded and its deadline is at
most five seconds. A matching, structurally valid NOERROR or NXDOMAIN reply
demonstrates end-to-end UDP traffic. It does not prove TCP connectivity or
policy/DNS leak protection. WireGuard handshakes prove only the local bridge.

A connected raw UDP socket may receive ICMP port-unreachable/reset while the
core restarts. Those errors are counted and ignored by its reader; owner-driven
socket closure still terminates it. If the WireGuard device closes itself after
a fatal adapter error, `Start` replaces it rather than retaining a dead device.
Tests cover Stop during a pending DNS probe and restart after self-closure.
