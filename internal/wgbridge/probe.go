package wgbridge

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type dnsProbe struct {
	resolver netip.Addr
	port     uint16
	id       uint16
	question dnsmessage.Question
	result   chan error
}

// ProbeDNS checks the actual CSQTT transport using one bounded raw IPv4/UDP
// query. A random question below example.com keeps it distinct from a native
// client's DNS flow even if its UDP source port happens to collide. A valid
// NXDOMAIN is a successful network probe; it is the expected answer normally.
func (b *Bridge) ProbeDNS(ctx context.Context, resolver netip.Addr) (time.Duration, error) {
	if !resolver.Is4() || resolver.IsUnspecified() || resolver.IsLoopback() || resolver.IsMulticast() {
		return 0, errors.New("probe requires an IPv4 DNS resolver")
	}
	b.mu.Lock()
	p := b.packets
	b.mu.Unlock()
	if p == nil {
		return 0, errors.New("WireGuard packet bridge is stopped")
	}
	// No caller can create an unbounded pending request or indefinite probe.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return 0, errors.New("cannot generate DNS probe identifier")
	}
	name, _ := dnsmessage.NewName("csqtt-" + hex.EncodeToString(random[:8]) + ".example.com.")
	probe := &dnsProbe{
		resolver: resolver,
		port:     49152 + binary.BigEndian.Uint16(random[8:10])%16384,
		id:       binary.BigEndian.Uint16(random[10:12]),
		question: dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
		result:   make(chan error, 1),
	}
	p.probeMu.Lock()
	if p.probe != nil {
		p.probeMu.Unlock()
		return 0, errors.New("a connectivity probe is already running")
	}
	p.probe = probe
	p.probeMu.Unlock()
	defer func() {
		p.probeMu.Lock()
		if p.probe == probe {
			p.probe = nil
		}
		p.probeMu.Unlock()
	}()
	message := dnsmessage.Message{Header: dnsmessage.Header{ID: probe.id, RecursionDesired: true}, Questions: []dnsmessage.Question{probe.question}}
	payload, err := message.Pack()
	if err != nil {
		return 0, errors.New("cannot encode DNS probe")
	}
	packet := makeUDPIPv4(p.address, resolver, probe.port, 53, payload)
	start := time.Now()
	if _, err = p.socket.Write(packet); err != nil {
		return 0, fmt.Errorf("send CSQTT connectivity probe: %w", err)
	}
	select {
	case err = <-probe.result:
		return time.Since(start), err
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-p.closed:
		return 0, net.ErrClosed
	}
}

func (p *packetDevice) consumeProbe(packet []byte) bool {
	if packet[9] != 17 || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
		return false
	}
	headerLen := int(packet[0]&15) * 4
	if len(packet) < headerLen+8 {
		return false
	}
	udp := packet[headerLen:]
	if int(binary.BigEndian.Uint16(udp[4:6])) != len(udp) || len(udp) < 20 {
		return false
	}
	p.probeMu.Lock()
	defer p.probeMu.Unlock()
	probe := p.probe
	if probe == nil || netip.AddrFrom4([4]byte(packet[12:16])) != probe.resolver || binary.BigEndian.Uint16(udp[:2]) != 53 || binary.BigEndian.Uint16(udp[2:4]) != probe.port || binary.BigEndian.Uint16(udp[8:10]) != probe.id {
		return false
	}
	var parser dnsmessage.Parser
	response, err := parser.Start(udp[8:])
	if err != nil {
		return false
	}
	question, err := parser.Question()
	if err != nil || question != probe.question {
		return false // Never consume another client's tuple on an ID collision.
	}
	if _, err = parser.Question(); err != dnsmessage.ErrSectionDone {
		err = errors.New("invalid DNS probe question count")
	} else if !response.Response || response.OpCode != 0 || response.Truncated {
		err = errors.New("invalid DNS probe response")
	} else if response.RCode != dnsmessage.RCodeSuccess && response.RCode != dnsmessage.RCodeNameError {
		err = errors.New("DNS resolver refused the connectivity probe")
	} else {
		// Validate the remaining DNS sections without retaining answer records.
		err = parser.SkipAllAnswers()
		if err == nil {
			err = parser.SkipAllAuthorities()
		}
		if err == nil {
			err = parser.SkipAllAdditionals()
		}
		if err != nil {
			err = errors.New("malformed DNS probe response")
		}
	}
	select {
	case probe.result <- err:
	default:
	}
	return true
}

func makeUDPIPv4(source, destination netip.Addr, sourcePort, destinationPort uint16, payload []byte) []byte {
	packet := make([]byte, 28+len(payload))
	packet[0], packet[8], packet[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	src, dst := source.As4(), destination.As4()
	copy(packet[12:16], src[:])
	copy(packet[16:20], dst[:])
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20]))
	udp := packet[20:]
	binary.BigEndian.PutUint16(udp[:2], sourcePort)
	binary.BigEndian.PutUint16(udp[2:4], destinationPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	// UDP over IPv4 permits a zero checksum. The authenticated CSQTT transport
	// protects these internal datagrams and the IP header still has a checksum.
	return packet
}
