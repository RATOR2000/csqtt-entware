package wgbridge

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type Config struct {
	PrivateKey             string
	PeerPublicKey          string
	ClientAddress          netip.Addr
	EncryptedListenAddress string
	CoreAddress            string
	PacketListenAddress    string
	MTU                    int
}

type Status struct {
	Running          bool      `json:"running"`
	LastHandshakeUTC time.Time `json:"last_handshake_utc"`
	RXBytes          uint64    `json:"rx_bytes"`
	TXBytes          uint64    `json:"tx_bytes"`
	DroppedPackets   uint64    `json:"dropped_packets"`
}

type Bridge struct {
	mu      sync.Mutex
	config  Config
	listen  netip.AddrPort
	core    netip.AddrPort
	packet  netip.AddrPort
	device  *device.Device
	packets *packetDevice
}

func New(cfg Config) (*Bridge, error) {
	if _, err := keyHex(cfg.PrivateKey); err != nil {
		return nil, err
	}
	if _, err := keyHex(cfg.PeerPublicKey); err != nil {
		return nil, err
	}
	public, err := PublicKey(cfg.PrivateKey)
	if err != nil || public == cfg.PeerPublicKey {
		return nil, errors.New("bridge and peer must have distinct WireGuard keys")
	}
	if !validClientAddress(cfg.ClientAddress) {
		return nil, errors.New("bridge requires the assigned CSQTT IPv4 address")
	}
	if cfg.MTU == 0 {
		cfg.MTU = DefaultMTU
	}
	if cfg.MTU < 576 || cfg.MTU > DefaultMTU {
		return nil, errors.New("bridge MTU must be between 576 and 1280")
	}
	listen, err := loopbackEndpoint(cfg.EncryptedListenAddress, "127.0.0.1:51820", false)
	if err != nil {
		return nil, err
	}
	core, err := loopbackEndpoint(cfg.CoreAddress, "127.0.0.1:39000", false)
	if err != nil {
		return nil, err
	}
	packet, err := loopbackEndpoint(cfg.PacketListenAddress, "127.0.0.1:39001", false)
	if err != nil {
		return nil, err
	}
	if listen == core || listen == packet || core == packet {
		return nil, errors.New("bridge UDP endpoints must use distinct ports")
	}
	return &Bridge{config: cfg, listen: listen, core: core, packet: packet}, nil
}

func (b *Bridge) Start() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.device != nil {
		select {
		case <-b.device.Wait():
			// A fatal adapter error can make wireguard-go close itself. Do not
			// retain that closed device forever when its core becomes available.
			b.device = nil
			b.packets = nil
		default:
			return nil
		}
	}
	socket, err := net.DialUDP("udp4", net.UDPAddrFromAddrPort(b.packet), net.UDPAddrFromAddrPort(b.core))
	if err != nil {
		return fmt.Errorf("open CSQTT packet adapter: %w", err)
	}
	_ = socket.SetReadBuffer(64 * 1024)
	_ = socket.SetWriteBuffer(64 * 1024)
	packets := &packetDevice{socket: socket, mtu: b.config.MTU, address: b.config.ClientAddress, events: make(chan tun.Event), closed: make(chan struct{})}
	bind := &loopbackBind{address: b.listen}
	dev := device.NewDevice(packets, bind, device.NewLogger(device.LogLevelSilent, ""))
	private, _ := keyHex(b.config.PrivateKey)
	peer, _ := keyHex(b.config.PeerPublicKey)
	uapi := fmt.Sprintf("private_key=%s\nlisten_port=%d\nreplace_peers=true\npublic_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s/32\n", private, b.listen.Port(), peer, b.config.ClientAddress)
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return errors.New("configure local WireGuard bridge")
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("start local WireGuard bridge: %w", err)
	}
	b.device = dev
	b.packets = packets
	return nil
}

func (b *Bridge) Stop() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.device == nil {
		return nil
	}
	b.device.Close()
	b.device = nil
	b.packets = nil
	return nil
}

func (b *Bridge) Status() Status {
	b.mu.Lock()
	defer b.mu.Unlock()
	var status Status
	if b.device == nil {
		return status
	}
	select {
	case <-b.device.Wait():
		return status
	default:
	}
	status.Running = true
	status.DroppedPackets = b.packets.dropped.Load()
	data, err := b.device.IpcGet()
	if err != nil {
		return status
	}
	var seconds, nanos int64
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}
		switch key {
		case "last_handshake_time_sec":
			seconds, _ = strconv.ParseInt(value, 10, 64)
		case "last_handshake_time_nsec":
			nanos, _ = strconv.ParseInt(value, 10, 64)
		case "rx_bytes":
			status.RXBytes, _ = strconv.ParseUint(value, 10, 64)
		case "tx_bytes":
			status.TXBytes, _ = strconv.ParseUint(value, 10, 64)
		}
	}
	if seconds > 0 {
		status.LastHandshakeUTC = time.Unix(seconds, nanos).UTC()
	}
	return status
}

type packetDevice struct {
	socket  *net.UDPConn
	address netip.Addr
	mtu     int
	events  chan tun.Event
	closed  chan struct{}
	once    sync.Once
	dropped atomic.Uint64
	probeMu sync.Mutex
	probe   *dnsProbe
}

func (*packetDevice) File() *os.File             { return nil }
func (*packetDevice) Name() (string, error)      { return "csqtt-packet", nil }
func (p *packetDevice) MTU() (int, error)        { return p.mtu, nil }
func (p *packetDevice) Events() <-chan tun.Event { return p.events }
func (*packetDevice) BatchSize() int             { return 1 }

func (p *packetDevice) Close() error {
	var err error
	p.once.Do(func() {
		close(p.closed)
		err = p.socket.Close()
		close(p.events)
	})
	return err
}

func (p *packetDevice) Read(packets [][]byte, sizes []int, offset int) (int, error) {
	if len(packets) < 1 || len(sizes) < 1 || offset < 0 || len(packets[0])-offset < p.mtu+1 {
		return 0, errors.New("invalid CSQTT packet receive buffer")
	}
	for {
		n, err := p.socket.Read(packets[0][offset : offset+p.mtu+1])
		if err != nil {
			// The peer is fixed loopback. A core restart can report an ICMP
			// port-unreachable/reset on this connected UDP socket; it does not
			// invalidate the socket or justify permanently closing WireGuard.
			// Explicit Close still unblocks this loop through net.ErrClosed.
			if transientCoreUDPError(err) {
				p.dropped.Add(1)
				continue
			}
			return 0, err
		}
		packet := packets[0][offset : offset+n]
		if !validIPv4(packet, p.mtu) || netip.AddrFrom4([4]byte(packet[16:20])) != p.address {
			p.dropped.Add(1)
			continue
		}
		if p.consumeProbe(packet) {
			continue
		}
		sizes[0] = n
		return 1, nil
	}
}

func transientCoreUDPError(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET)
}

func (p *packetDevice) Write(packets [][]byte, offset int) (int, error) {
	for _, buffer := range packets {
		if offset < 0 || offset > len(buffer) {
			p.dropped.Add(1)
			continue
		}
		packet := buffer[offset:]
		if !validIPv4(packet, p.mtu) || netip.AddrFrom4([4]byte(packet[12:16])) != p.address {
			p.dropped.Add(1)
			continue
		}
		if _, err := p.socket.Write(packet); err != nil {
			p.dropped.Add(1)
		}
	}
	return len(packets), nil
}

func validIPv4(packet []byte, mtu int) bool {
	if len(packet) < 20 || len(packet) > mtu || packet[0]>>4 != 4 {
		return false
	}
	header := int(packet[0]&15) * 4
	return header >= 20 && header <= len(packet) && int(binary.BigEndian.Uint16(packet[2:4])) == len(packet) && checksum(packet[:header]) == 0
}

func checksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&65535 + sum>>16
	}
	return ^uint16(sum)
}

var _ tun.Device = (*packetDevice)(nil)
