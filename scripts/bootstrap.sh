#!/bin/sh
# Download one explicit release from this repository, then use its installer.
set -eu
PATH=/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

fail() { printf '%s\n' "CSQTT: $1" >&2; exit 1; }

validate_tag() {
    [ "$#" -eq 1 ] || return 1
    version=${1#v}
    [ "$version" != "$1" ] && [ "${#version}" -ge 1 ] && [ "${#version}" -le 64 ] || return 1
    case "$version" in [0-9]*) ;; *) return 1 ;; esac
    case "$version" in *[!0-9A-Za-z.+~_-]*) return 1 ;; esac
}

fetch_release() (
    url=$1 destination=$2 file_blocks=$3
    ulimit -c 0
    # POSIX uses 512-byte blocks; ash implementations using 1024-byte blocks
    # remain bounded to 32 MiB for the IPK and 128 KiB for installer/headers.
    ulimit -f "$file_blocks" || fail 'cannot limit release download size'
    redirects=0
    while [ "$redirects" -le 2 ]; do
        if "$wget_bin" --no-config --no-netrc --no-proxy --no-hsts \
            --check-certificate --ca-certificate="$ca_bundle" \
            --timeout=20 --tries=2 --max-redirect=0 --server-response \
            --output-document="$destination" "$url" 2>"$stage/headers"; then
            [ -s "$destination" ] || fail 'release asset is empty'
            exit 0
        fi
        # --https-only governs recursive links, not redirects. Follow only
        # GitHub's HTTPS release-asset host, with automatic redirects disabled.
        url=$(awk '
            /^[ \t]+HTTP\// {redirect=($2 ~ /^30[12378]$/); count=0; location=""}
            /^[ \t]+/ && tolower($1) == "location:" && redirect {count++; location=$2; if (NF != 2) count=99}
            END {if (redirect && count == 1 && location !~ /[[:space:][:cntrl:]]/) print location; else exit 1}
        ' "$stage/headers") || fail 'release download failed; check the tag, network and TLS CA certificates'
        [ "${#url}" -le 8192 ] || fail 'invalid release redirect'
        case "$url" in
            https://release-assets.githubusercontent.com/github-production-release-asset/*) ;;
            *) fail 'release redirect must stay on the HTTPS GitHub asset host' ;;
        esac
        redirects=$((redirects + 1))
    done
    fail 'too many release redirects'
)

verify_checksum() {
    checked_file=$1 checksum_file=$2 checked_name=$3
    expected=$(awk -v name="$checked_name" '
        NF != 2 || $2 != name || length($1) != 64 || $1 ~ /[^0-9a-fA-F]/ {bad=1}
        {digest=tolower($1)}
        END {if (!bad && NR == 1) print digest; else exit 1}
    ' "$checksum_file") || fail 'invalid release checksum file'
    actual=$(sha256sum "$checked_file" | awk '{print $1}')
    [ "$actual" = "$expected" ] || fail 'release asset SHA256 mismatch'
}

cleanup() {
    case "${stage:-}" in
        /tmp/csqtt-bootstrap.??????) [ ! -L "$stage" ] && rm -rf -- "$stage" ;;
    esac
}

bootstrap_main() {
    [ "$#" -ge 1 ] && [ "$#" -le 2 ] || fail 'Usage: bootstrap.sh vRELEASE_VERSION [LAN_IP:PORT]'
    validate_tag "$1" || fail 'use one explicit vRELEASE_VERSION tag; latest, branches and paths are not accepted'
    tag=$1
    package=csqtt-entware_${version}_mipsel-3.4.ipk
    base=https://github.com/RATOR2000/csqtt-entware/releases/download/$tag
    wget_bin=/opt/bin/wget
    ca_bundle=/opt/etc/ssl/certs/ca-certificates.crt
    [ -x "$wget_bin" ] && [ -s "$ca_bundle" ] || fail 'Entware wget-ssl and CA certificates are required'
    for tool in awk sha256sum mktemp wc; do command -v "$tool" >/dev/null 2>&1 || fail "required tool is missing: $tool"; done
    stage=$(mktemp -d /tmp/csqtt-bootstrap.XXXXXX) || fail 'cannot create private RAM staging directory'
    case "$stage" in /tmp/csqtt-bootstrap.??????) ;; *) fail 'unexpected staging directory' ;; esac
    trap cleanup 0
    trap 'exit 1' HUP INT TERM
    fetch_release "$base/$package.sha256" "$stage/package.sha256" 128
    fetch_release "$base/install.sh.sha256" "$stage/install.sh.sha256" 128
    fetch_release "$base/install.sh" "$stage/install.sh" 128
    verify_checksum "$stage/install.sh" "$stage/install.sh.sha256" install.sh
    fetch_release "$base/$package" "$stage/$package" 32768
    verify_checksum "$stage/$package" "$stage/package.sha256" "$package"
    # The existing installer owns preflight, settings backup and preservation.
    # Credentials are entered later in the local panel, never as arguments.
    if [ "$#" -eq 2 ]; then
        sh "$stage/install.sh" "$stage/$package" "$expected" "$2"
    else
        sh "$stage/install.sh" "$stage/$package" "$expected"
    fi
}

bootstrap_main "$@"
