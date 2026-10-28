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

Binary IPKs also install the three Go module PATENTS files and verified notice
bundles under `/opt/share/licenses/csqtt-entware/{core,manager}-notices/`.
Each bundle has a `manifest.json` mapping original component paths to verbatim,
content-addressed notice texts, with the executable SHA256, locked input hashes,
collector source revision and pinned toolchain version. Source links alone do
not replace these distributed notices.

The core bundle uses Cargo's locked, offline target resolve graph and the
already-downloaded crate sources. It preserves nested license/NOTICE files,
including bundled native code; build/test dependencies in that graph are kept
as a conservative superset. Rust's pinned `COPYRIGHT-library.html` and runtime
license texts cover the rebuilt standard library and its dependencies. The
manager bundle preserves the pinned Go toolchain LICENSE/PATENTS and nested
source notices, also as a conservative superset. Bundle collection performs no
license-expression substitution or network license lookup.

The patched `primp` 1.3.1 source retains its original MIT notice, restored from
[the published 1.3.1 crate](https://static.crates.io/crates/primp/primp-1.3.1.crate)
(crate SHA256 `de5af71998859143057235d9e4985849c2c5da1f882425c93bcb3dfda229d525`).

The published `alloc-stdlib` 0.2.4 subcrate omits its repository-root LICENSE.
`packaging/notices/alloc-stdlib-0.2.4/LICENSE` preserves the verbatim Dropbox
notice from [the revision pinned by that crate's `.cargo_vcs_info.json`](https://github.com/dropbox/rust-alloc-no-stdlib/blob/ae42d22078b98549e987d2f03d12df7b984fde47/LICENSE).
The collector permits this explicit supplement only for the exact locked crate
checksum and verified notice checksum, and records its origin in the manifest.
