// Package wgbridge connects a single local WireGuard peer to CSQTT's raw-IP
// datagram adapter. Decrypted traffic never enters the operating system stack.
package wgbridge

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
)

const DefaultMTU = 1280

type KeyPair struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

func GenerateKeys() (KeyPair, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, errors.New("cannot generate WireGuard key")
	}
	private := key.Bytes()
	private[0] &= 248
	private[31] = private[31]&127 | 64
	encoded := base64.StdEncoding.EncodeToString(private)
	public, err := PublicKey(encoded)
	return KeyPair{PrivateKey: encoded, PublicKey: public}, err
}

func decodeKey(encoded string) ([]byte, error) {
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != encoded {
		return nil, errors.New("invalid WireGuard key")
	}
	var any byte
	for _, b := range key {
		any |= b
	}
	if any == 0 {
		return nil, errors.New("empty WireGuard key")
	}
	return key, nil
}

func PublicKey(private string) (string, error) {
	key, err := decodeKey(private)
	if err != nil {
		return "", err
	}
	sk, err := ecdh.X25519().NewPrivateKey(key)
	if err != nil {
		return "", errors.New("invalid WireGuard private key")
	}
	return base64.StdEncoding.EncodeToString(sk.PublicKey().Bytes()), nil
}

func keyHex(encoded string) (string, error) {
	key, err := decodeKey(encoded)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

type ClientProfile struct {
	PrivateKey      string
	ServerPublicKey string
	Address         netip.Addr
	Endpoint        string
	DNS             netip.Addr
	MTU             int
}

func GenerateClientConfig(p ClientProfile) (string, error) {
	if _, err := decodeKey(p.PrivateKey); err != nil {
		return "", err
	}
	if _, err := decodeKey(p.ServerPublicKey); err != nil {
		return "", err
	}
	if !validClientAddress(p.Address) {
		return "", errors.New("profile requires the assigned CSQTT IPv4 address")
	}
	endpoint, err := loopbackEndpoint(p.Endpoint, "127.0.0.1:51820", false)
	if err != nil {
		return "", err
	}
	if !p.DNS.IsValid() {
		p.DNS = netip.MustParseAddr("9.9.9.9")
	}
	if !p.DNS.Is4() || p.DNS.IsUnspecified() || p.DNS.IsLoopback() || p.DNS.IsMulticast() {
		return "", errors.New("profile DNS must be an IPv4 resolver")
	}
	if p.MTU == 0 {
		p.MTU = DefaultMTU
	}
	if p.MTU < 576 || p.MTU > DefaultMTU {
		return "", errors.New("profile MTU must be between 576 and 1280")
	}
	// Only fields understood by Keenetic's standard WireGuard importer belong
	// here: no wg-quick scripts, shell commands, or system-wide route changes.
	return fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s/32\nDNS = %s\nMTU = %d\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0\nEndpoint = %s\nPersistentKeepalive = 15\n", p.PrivateKey, p.Address, p.DNS, p.MTU, p.ServerPublicKey, endpoint), nil
}

func validClientAddress(addr netip.Addr) bool {
	return addr.Is4() && !addr.IsUnspecified() && !addr.IsLoopback() && !addr.IsMulticast() && addr != netip.MustParseAddr("255.255.255.255")
}

func loopbackEndpoint(value, fallback string, allowZeroPort bool) (netip.AddrPort, error) {
	if value == "" {
		value = fallback
	}
	addr, err := netip.ParseAddrPort(value)
	if err != nil || !addr.Addr().Is4() || !addr.Addr().IsLoopback() || (!allowZeroPort && addr.Port() == 0) {
		return netip.AddrPort{}, errors.New("bridge endpoints must be numeric IPv4 loopback addresses with a port")
	}
	return addr, nil
}
