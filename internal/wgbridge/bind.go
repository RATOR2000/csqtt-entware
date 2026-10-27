package wgbridge

import (
	"errors"
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

// loopbackBind deliberately avoids StdNetBind: that implementation binds all
// addresses and enables large platform batches. This adapter is local-only.
type loopbackBind struct {
	mu      sync.Mutex
	address netip.AddrPort
	socket  *net.UDPConn
}

type endpoint struct{ address netip.AddrPort }

func (e *endpoint) ClearSrc()           {}
func (e *endpoint) SrcToString() string { return "127.0.0.1" }
func (e *endpoint) DstToString() string { return e.address.String() }
func (e *endpoint) DstToBytes() []byte {
	b, _ := e.address.MarshalBinary()
	return b
}
func (e *endpoint) DstIP() netip.Addr { return e.address.Addr() }
func (e *endpoint) SrcIP() netip.Addr { return netip.MustParseAddr("127.0.0.1") }

func (b *loopbackBind) ParseEndpoint(value string) (conn.Endpoint, error) {
	addr, err := loopbackEndpoint(value, "", false)
	if err != nil {
		return nil, err
	}
	return &endpoint{address: addr}, nil
}

func (*loopbackBind) BatchSize() int { return 1 }
func (*loopbackBind) SetMark(mark uint32) error {
	if mark != 0 {
		return errors.New("local WireGuard bridge does not accept routing marks")
	}
	return nil
}

func (b *loopbackBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.socket != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	addr := netip.AddrPortFrom(b.address.Addr(), port)
	socket, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(addr))
	if err != nil {
		return nil, 0, err
	}
	_ = socket.SetReadBuffer(64 * 1024)
	_ = socket.SetWriteBuffer(64 * 1024)
	b.socket = socket
	actual := socket.LocalAddr().(*net.UDPAddr).AddrPort()
	// One byte beyond the vendored maximum distinguishes truncation from a
	// valid maximum-sized datagram without a 64 KiB allocation per reader.
	var scratch [2049]byte
	receive := func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
		if len(packets) == 0 || len(sizes) == 0 || len(endpoints) == 0 {
			return 0, errors.New("empty WireGuard receive batch")
		}
		for {
			n, source, err := socket.ReadFromUDPAddrPort(scratch[:])
			if err != nil {
				return 0, err
			}
			if n > 2048 || n > len(packets[0]) || !source.Addr().IsLoopback() || !source.Addr().Is4() {
				continue
			}
			copy(packets[0], scratch[:n])
			sizes[0] = n
			endpoints[0] = &endpoint{address: source}
			return 1, nil
		}
	}
	return []conn.ReceiveFunc{receive}, actual.Port(), nil
}

func (b *loopbackBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.socket == nil {
		return nil
	}
	err := b.socket.Close()
	b.socket = nil
	return err
}

func (b *loopbackBind) Send(packets [][]byte, remote conn.Endpoint) error {
	ep, ok := remote.(*endpoint)
	if !ok || !ep.address.Addr().IsLoopback() || !ep.address.Addr().Is4() {
		return conn.ErrWrongEndpointType
	}
	b.mu.Lock()
	socket := b.socket
	b.mu.Unlock()
	if socket == nil {
		return net.ErrClosed
	}
	for _, packet := range packets {
		if len(packet) > 2048 {
			return errors.New("WireGuard datagram exceeds bridge buffer")
		}
		if _, err := socket.WriteToUDPAddrPort(packet, ep.address); err != nil {
			return err
		}
	}
	return nil
}

var _ conn.Bind = (*loopbackBind)(nil)
