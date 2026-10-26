# Source provenance and licenses

`vendor/csqtt` and the adapted CAPTCHA helper broker originate from
https://github.com/RATOR2000/csqtt-openwrt at commit
`d3121f1c9b9a0c445bd7da2631b58882411379ab` (read-only snapshot).

The CSQTT protocol implementation is based on original amurcanov/csqtt 2.1.9,
commit `446293aa2e873ac5323ef6fd2316d9b81d966c11`:
https://github.com/amurcanov/csqtt/tree/446293aa2e873ac5323ef6fd2316d9b81d966c11

CSQTT and its derivatives are PolyForm Noncommercial 1.0.0; see LICENSE and
vendor/csqtt/LICENSE. Required notices remain intact. This project is not
affiliated with Keenetic or VK.

WireGuard Go and Go module dependencies retain their upstream licenses in the
vendored source and module metadata. The WireGuard engine has a documented
bounded queue/buffer profile for this embedded target.
