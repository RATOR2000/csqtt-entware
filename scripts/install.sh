#!/bin/sh
# Install an explicit, locally supplied candidate. No latest/release URL exists.
set -eu
PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077
fail() { printf '%s\n' "CSQTT: $1" >&2; exit 1; }
verify_payload() {
    # An optional filesystem prefix makes this pure postcondition testable on
    # the host. Production calls it without a prefix and checks the real /opt.
    verify_root=${1:-}
    inventory=$(opkg files csqtt-entware 2>/dev/null) || return 1
    paths=$(printf '%s\n' "$inventory" | awk '
        /^\// {
            if (($0 != "/opt" && $0 !~ /^\/opt\//) || $0 ~ /\/\.\.?($|\/)/ || $0 ~ /[\r\t]/) bad=1;
            else {print; count++}
        }
        END {exit (bad || count == 0)}') || return 1
    printf '%s\n' "$paths" | while IFS= read -r installed; do
        test -r "$verify_root$installed" || exit 1
    done || return 1
    for installed in /opt/bin/csqtt-client /opt/bin/csqtt-entware /opt/etc/init.d/S90csqtt; do
        test -x "$verify_root$installed" || return 1
    done
    for license in LICENSE THIRD_PARTY.md golang.zx2c4.com/wireguard/LICENSE \
        golang.zx2c4.com/wintun/LICENSE golang.org/x/crypto/LICENSE \
        golang.org/x/net/LICENSE golang.org/x/sys/LICENSE; do
        test -s "$verify_root/opt/share/licenses/csqtt-entware/$license" || return 1
    done
}
check_only=0
if [ "${1:-}" = --check ]; then check_only=1; shift; fi
[ "$#" -ge 2 ] && [ "$#" -le 3 ] || fail 'Usage: install.sh [--check] /absolute/package.ipk SHA256 [LAN_IP:PORT]'
artifact=$1
expected=$2
case "$artifact" in /*.ipk) ;; *) fail 'use an absolute local IPK path' ;; esac
[ -f "$artifact" ] && [ ! -L "$artifact" ] || fail 'package file is missing or is a symlink'
[ "${#expected}" -eq 64 ] || fail 'SHA256 must contain 64 hexadecimal characters'
case "$expected" in *[!a-fA-F0-9]*) fail 'invalid SHA256' ;; esac
for tool in sha256sum opkg ndmc ip awk df tar; do command -v "$tool" >/dev/null 2>&1 || fail "required tool is missing: $tool"; done
[ "$(id -u)" = 0 ] || fail 'run as Entware root'
actual=$(sha256sum "$artifact" | awk '{print $1}')
expected=$(printf '%s' "$expected" | tr A-F a-f)
[ "$actual" = "$expected" ] || fail 'package SHA256 mismatch'
[ -d /opt/etc ] && [ -d /opt/bin ] || fail 'Entware /opt is not mounted'
case "$(uname -m)" in mips|mipsel) ;; *) fail 'this candidate requires MIPS32 little-endian Entware' ;; esac
opkg print-architecture | awk '$2 == "mipsel-3.4" && $3 ~ /^[0-9]+$/ {found=1} END {exit !found}' || fail 'Entware architecture must include mipsel-3.4'
version=$(ndmc -c 'show version' 2>/dev/null) || fail 'cannot read Keenetic version'
title=$(printf '%s\n' "$version" | awk '$1 == "title:" {print $2; exit}')
case "$title" in 3.8.*) ;; *) fail 'this candidate is restricted to KeeneticOS 3.8.x' ;; esac
printf '%s\n' "$version" | awk 'index(tolower($0), "wireguard") {found=1} END {exit !found}' || fail 'native WireGuard component is required'
awk '/^MemTotal:/ {total=$2} /^MemAvailable:/ {available=$2} END {exit !(total >= 120000 && available >= 16384)}' /proc/meminfo || fail 'requires 128 MB RAM class and at least 16 MB currently available'

listen=${3:-192.168.2.1:8080}
if [ "$#" -eq 2 ] && [ -r /opt/etc/csqtt/listen ]; then IFS= read -r listen < /opt/etc/csqtt/listen || :; fi
printf '%s\n' "$listen" | awk -F: '
    NF != 2 || $2 !~ /^[0-9]+$/ || $2 < 1 || $2 > 65535 {exit 1}
    {n=split($1,a,"."); if(n != 4) exit 1; for(i=1;i<=4;i++) if(a[i] !~ /^[0-9]+$/ || a[i] > 255 || (length(a[i]) > 1 && substr(a[i],1,1) == "0")) exit 1;
    if(!(a[1] == 10 || (a[1] == 172 && a[2] >= 16 && a[2] <= 31) || (a[1] == 192 && a[2] == 168))) exit 1}' || fail 'listener must be a private LAN IPv4 address and valid port'
lan=${listen%:*}
ip -4 addr show | awk -v address="$lan" '$1 == "inet" {split($2,a,"/"); if(a[1] == address) found=1} END {exit !found}' || fail 'listener address is not assigned to this router'
home=$(ndmc -c 'show interface Bridge0' 2>/dev/null) || fail 'cannot read native home interface'
printf '%s\n' "$home" | awk -v address="$lan" '
    $1 == "security-level:" && $2 == "private" {private=1}
    $1 == "address:" && $2 == address {home=1}
    END {exit !(private && home)}' || fail 'listener must belong to the private Bridge0 home interface'
package_kb=$(( ($(wc -c < "$artifact") + 1023) / 1024 ))
available_kb=$(df -Pk /opt | awk 'END {print $4}')
case "$available_kb" in ''|*[!0-9]*) fail 'cannot read USB free space' ;; esac
[ "$available_kb" -ge $((package_kb * 4 + 8192)) ] || fail 'insufficient USB staging space'
# Native opkg resolves dependencies and validates the package without installing.
opkg --noaction install "$artifact" >/dev/null || fail 'package dependency/architecture preflight failed'
if [ "$check_only" -eq 1 ]; then
    printf '%s\n' 'CSQTT candidate preflight passed; no installation performed.'
    exit 0
fi

if [ -d /opt/etc/csqtt ]; then
    backup_dir=/opt/var/backups/csqtt
    mkdir -p "$backup_dir"
    chmod 700 "$backup_dir"
    backup=$backup_dir/config-$(date -u +%Y%m%dT%H%M%SZ)-$$.tar.gz
    tar -czf "$backup" -C /opt/etc csqtt || fail 'settings backup failed'
    chmod 600 "$backup"
fi
mkdir -p /opt/etc/csqtt
chmod 700 /opt/etc/csqtt
if [ "$#" -eq 3 ] || [ ! -f /opt/etc/csqtt/listen ]; then
    printf '%s\n' "$listen" > /opt/etc/csqtt/listen
    chmod 600 /opt/etc/csqtt/listen
fi
# Repeating the one-command installation must also repair the same version.
# Owner settings are not package payload and have already been backed up.
opkg --force-reinstall install "$artifact" || fail 'installation failed; settings backup was retained'
verify_payload || fail 'incomplete package extraction; settings backup was retained'
printf '%s\n' "CSQTT manager installed: http://$listen/"
printf '%s\n' 'This confirms package installation only. Configure CSQTT and verify the full VPN path in the panel.'
