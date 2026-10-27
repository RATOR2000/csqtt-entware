package wgbridge

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

func udpSocket(t *testing.T) *net.UDPConn {
	t.Helper()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = socket.Close() })
	return socket
}

func freeEndpoint(t *testing.T) string {
	t.Helper()
	socket := udpSocket(t)
	address := socket.LocalAddr().String()
	_ = socket.Close()
	return address
}

func newFixture(t *testing.T) (*Bridge, *net.UDPConn, KeyPair, KeyPair) {
	t.Helper()
	server, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	client, err := GenerateKeys()
	if err != nil {
		t.Fatal(err)
	}
	core := udpSocket(t)
	bridge, err := New(Config{
		PrivateKey: server.PrivateKey, PeerPublicKey: client.PublicKey,
		ClientAddress:          netip.MustParseAddr("11.8.0.2"),
		EncryptedListenAddress: freeEndpoint(t), CoreAddress: core.LocalAddr().String(), PacketListenAddress: freeEndpoint(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := bridge.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bridge.Stop() })
	return bridge, core, server, client
}

type memoryTUN struct {
	read   chan []byte
	write  chan []byte
	events chan tun.Event
	done   chan struct{}
	once   sync.Once
}

func newMemoryTUN() *memoryTUN {
	return &memoryTUN{read: make(chan []byte, 8), write: make(chan []byte, 8), events: make(chan tun.Event), done: make(chan struct{})}
}
func (*memoryTUN) File() *os.File             { return nil }
func (*memoryTUN) Name() (string, error)      { return "test", nil }
func (*memoryTUN) MTU() (int, error)          { return DefaultMTU, nil }
func (*memoryTUN) BatchSize() int             { return 1 }
func (m *memoryTUN) Events() <-chan tun.Event { return m.events }
func (m *memoryTUN) Close() error {
	m.once.Do(func() { close(m.done); close(m.events) })
	return nil
}
func (m *memoryTUN) Read(packets [][]byte, sizes []int, offset int) (int, error) {
	select {
	case packet := <-m.read:
		sizes[0] = copy(packets[0][offset:], packet)
		return 1, nil
	case <-m.done:
		return 0, os.ErrClosed
	}
}
func (m *memoryTUN) Write(packets [][]byte, offset int) (int, error) {
	for _, packet := range packets {
		copyPacket := append([]byte(nil), packet[offset:]...)
		select {
		case m.write <- copyPacket:
		case <-m.done:
			return 0, os.ErrClosed
		}
	}
	return len(packets), nil
}

func nativePeer(t *testing.T, bridge *Bridge, server, client KeyPair) (*device.Device, *memoryTUN) {
	t.Helper()
	memory := newMemoryTUN()
	bind := &loopbackBind{address: netip.MustParseAddrPort("127.0.0.1:0")}
	peer := device.NewDevice(memory, bind, device.NewLogger(device.LogLevelSilent, ""))
	private, _ := keyHex(client.PrivateKey)
	public, _ := keyHex(server.PublicKey)
	config := fmt.Sprintf("private_key=%s\npublic_key=%s\nallowed_ip=0.0.0.0/0\nendpoint=%s\n", private, public, bridge.listen)
	if err := peer.IpcSet(config); err != nil {
		t.Fatal(err)
	}
	if err := peer.Up(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(peer.Close)
	return peer, memory
}

func TestEncryptedPacketRoundTrip(t *testing.T) {
	bridge, core, server, client := newFixture(t)
	_, native := nativePeer(t, bridge, server, client)
	remote := netip.MustParseAddr("9.9.9.9")
	request := makeUDPIPv4(bridge.config.ClientAddress, remote, 25001, 53, []byte("request"))
	native.read <- request
	_ = core.SetReadDeadline(time.Now().Add(5 * time.Second))
	buffer := make([]byte, 1500)
	n, source, err := core.ReadFromUDP(buffer)
	if err != nil {
		t.Fatalf("local WireGuard packet did not reach raw CSQTT endpoint: %v", err)
	}
	if !bytes.Equal(request, buffer[:n]) {
		t.Fatal("bridge changed the IP packet")
	}
	response := makeUDPIPv4(remote, bridge.config.ClientAddress, 53, 25001, []byte("response"))
	if _, err = core.WriteToUDP(response, source); err != nil {
		t.Fatal(err)
	}
	select {
	case packet := <-native.write:
		if !bytes.Equal(packet, response) {
			t.Fatal("native peer received a changed reply")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("raw reply did not return over encrypted WireGuard")
	}
	status := bridge.Status()
	if !status.Running || status.LastHandshakeUTC.IsZero() || status.RXBytes == 0 || status.TXBytes == 0 {
		t.Fatalf("missing local handshake and traffic status: %+v", status)
	}
}

func TestOnlyAssignedIPv4ReachesCore(t *testing.T) {
	bridge, core, server, client := newFixture(t)
	_, native := nativePeer(t, bridge, server, client)
	wrong := makeUDPIPv4(netip.MustParseAddr("192.168.2.9"), netip.MustParseAddr("9.9.9.9"), 12000, 53, []byte("bad source"))
	native.read <- wrong
	good := makeUDPIPv4(bridge.config.ClientAddress, netip.MustParseAddr("9.9.9.9"), 12000, 53, []byte("correct source"))
	native.read <- good
	_ = core.SetReadDeadline(time.Now().Add(5 * time.Second))
	buffer := make([]byte, 1500)
	n, _, err := core.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(good, buffer[:n]) {
		t.Fatal("a packet with the wrong source escaped the peer allowlist")
	}
}

func TestProbeUsesRealRawEndpointAndConsumesOnlyItsReply(t *testing.T) {
	bridge, core, _, _ := newFixture(t)
	done := make(chan error, 1)
	go func() {
		buffer := make([]byte, 1500)
		_ = core.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, source, err := core.ReadFromUDP(buffer)
		if err != nil {
			done <- err
			return
		}
		packet := buffer[:n]
		if !validIPv4(packet, DefaultMTU) {
			done <- fmt.Errorf("invalid probe IP packet")
			return
		}
		var query dnsmessage.Message
		if err := query.Unpack(packet[28:]); err != nil {
			done <- err
			return
		}
		query.Header.Response = true
		query.Header.RCode = dnsmessage.RCodeNameError
		payload, err := query.Pack()
		if err != nil {
			done <- err
			return
		}
		resolver := netip.AddrFrom4([4]byte(packet[16:20]))
		reply := makeUDPIPv4(resolver, bridge.config.ClientAddress, 53, binary.BigEndian.Uint16(packet[20:22]), payload)
		_, err = core.WriteToUDP(reply, source)
		done <- err
	}()
	elapsed, err := bridge.ProbeDNS(context.Background(), netip.MustParseAddr("9.9.9.9"))
	if err != nil || elapsed < 0 {
		t.Fatalf("raw probe failed: %v", err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if bridge.Status().TXBytes != 0 {
		t.Fatal("probe reply leaked into the WireGuard peer queue")
	}
}

func TestProbeCancellationAndSinglePendingRequest(t *testing.T) {
	bridge, core, _, _ := newFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := bridge.ProbeDNS(ctx, netip.MustParseAddr("9.9.9.9")); done <- err }()
	_ = core.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := core.ReadFromUDP(make([]byte, 1500)); err != nil {
		t.Fatal(err)
	}
	if _, err := bridge.ProbeDNS(context.Background(), netip.MustParseAddr("9.9.9.9")); err == nil {
		t.Fatal("allowed a second pending probe")
	}
	cancel()
	if err := <-done; err != context.Canceled {
		t.Fatalf("unexpected cancellation result: %v", err)
	}
}

func TestBoundedProfileAndSaturatedStagingShutdown(t *testing.T) {
	if device.MaxSegmentSize != 2048 || device.PreallocatedBuffersPerPool != 512 || device.QueueStagedSize != 64 || device.QueueOutboundSize != 64 || device.QueueInboundSize != 64 || device.QueueHandshakeSize != 64 {
		t.Fatal("the qualified bounded WireGuard vendor profile has been lost")
	}
	bridge, core, _, _ := newFixture(t)
	packet := makeUDPIPv4(netip.MustParseAddr("9.9.9.9"), bridge.config.ClientAddress, 53, 12345, []byte("flood"))
	for i := 0; i < 3000; i++ {
		if _, err := core.WriteToUDPAddrPort(packet, bridge.packet); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan struct{})
	go func() { _ = bridge.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("pool exhaustion or shutdown deadlock under saturated staging")
	}
	if bridge.Status().Running {
		t.Fatal("bridge still reports running after stop")
	}
	if err := bridge.Start(); err != nil {
		t.Fatalf("bridge could not restart: %v", err)
	}
}

func TestClientProfileAndLoopbackValidation(t *testing.T) {
	server, _ := GenerateKeys()
	client, _ := GenerateKeys()
	profile := ClientProfile{PrivateKey: client.PrivateKey, ServerPublicKey: server.PublicKey, Address: netip.MustParseAddr("11.8.0.2")}
	config, err := GenerateClientConfig(profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"Address = 11.8.0.2/32", "Endpoint = 127.0.0.1:51820", "AllowedIPs = 0.0.0.0/0", "MTU = 1280", "DNS = 9.9.9.9"} {
		if !strings.Contains(config, value) {
			t.Fatalf("missing importer field: %s", value)
		}
	}
	profile.Endpoint = "0.0.0.0:51820"
	if _, err = GenerateClientConfig(profile); err == nil {
		t.Fatal("accepted an externally reachable bridge endpoint")
	}
	profile.Endpoint = "127.0.0.1:51820"
	profile.PrivateKey += "\n"
	if _, err = GenerateClientConfig(profile); err == nil {
		t.Fatal("accepted noncanonical key text that could alter a config line")
	}
}

func TestIPv4Validation(t *testing.T) {
	packet := makeUDPIPv4(netip.MustParseAddr("11.8.0.2"), netip.MustParseAddr("9.9.9.9"), 20000, 53, []byte("hello"))
	if !validIPv4(packet, DefaultMTU) {
		t.Fatal("valid packet rejected")
	}
	packet[10] ^= 1
	if validIPv4(packet, DefaultMTU) {
		t.Fatal("bad header checksum accepted")
	}
	packet[10] ^= 1
	if validIPv4(packet[:19], DefaultMTU) || validIPv4(packet, 20) {
		t.Fatal("truncated or oversized packet accepted")
	}
}

func TestStopCancelsPendingProbeAndCanRestart(t *testing.T) {
	bridge, core, _, _ := newFixture(t)
	done := make(chan error, 1)
	go func() { _, err := bridge.ProbeDNS(context.Background(), netip.MustParseAddr("9.9.9.9")); done <- err }()
	_ = core.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := core.ReadFromUDP(make([]byte, 1500)); err != nil {
		t.Fatal(err)
	}
	stopped := make(chan struct{})
	go func() { _ = bridge.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("Stop deadlocked with an active DNS probe")
	}
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("probe did not observe bridge closure: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("probe remained blocked after Stop")
	}
	if err := bridge.Start(); err != nil {
		t.Fatalf("could not restart after pending-probe shutdown: %v", err)
	}
}

func TestStartReplacesSelfClosedDevice(t *testing.T) {
	bridge, _, _, _ := newFixture(t)
	old := bridge.device
	// Model a fatal socket error independent of an ordinary, owner-driven Stop.
	if err := bridge.packets.socket.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-old.Wait():
	case <-time.After(3 * time.Second):
		t.Fatal("device did not close after fatal packet-adapter failure")
	}
	if bridge.Status().Running {
		t.Fatal("closed device still appears running")
	}
	if err := bridge.Start(); err != nil {
		t.Fatalf("restart closed device: %v", err)
	}
	if bridge.device == old || !bridge.Status().Running {
		t.Fatal("Start retained a self-closed WireGuard device")
	}
}

func TestTransientCoreUDPErrorsDoNotIncludeOwnerClose(t *testing.T) {
	for _, errno := range []error{syscall.ECONNREFUSED, syscall.ECONNRESET} {
		if !transientCoreUDPError(&net.OpError{Op: "read", Net: "udp4", Err: errno}) {
			t.Fatalf("core restart error not recognized: %v", errno)
		}
	}
	if transientCoreUDPError(net.ErrClosed) || transientCoreUDPError(context.Canceled) {
		t.Fatal("owner shutdown must terminate the packet reader")
	}
}

func TestEncryptedFragmentsAndICMPPreservePacketBytes(t *testing.T) {
	bridge, core, server, client := newFixture(t)
	_, native := nativePeer(t, bridge, server, client)
	remote := netip.MustParseAddr("9.9.9.9")
	whole := makeUDPIPv4(remote, bridge.config.ClientAddress, 53, 25001, bytes.Repeat([]byte{0x53}, 40))
	first := append([]byte(nil), whole[:44]...)
	binary.BigEndian.PutUint16(first[2:4], uint16(len(first)))
	binary.BigEndian.PutUint16(first[6:8], 0x2000)
	first[10], first[11] = 0, 0
	binary.BigEndian.PutUint16(first[10:12], checksum(first[:20]))
	second := append(append([]byte(nil), whole[:20]...), whole[44:]...)
	binary.BigEndian.PutUint16(second[2:4], uint16(len(second)))
	binary.BigEndian.PutUint16(second[6:8], 3)
	second[10], second[11] = 0, 0
	binary.BigEndian.PutUint16(second[10:12], checksum(second[:20]))
	icmp := makeUDPIPv4(remote, bridge.config.ClientAddress, 0, 0, whole[:28])
	icmp[9] = 1
	icmp[20], icmp[21] = 3, 4
	icmp[22], icmp[23] = 0, 0
	icmp[24], icmp[25] = 0, 0
	binary.BigEndian.PutUint16(icmp[26:28], DefaultMTU)
	binary.BigEndian.PutUint16(icmp[22:24], checksum(icmp[20:]))
	icmp[10], icmp[11] = 0, 0
	binary.BigEndian.PutUint16(icmp[10:12], checksum(icmp[:20]))
	// Trigger the authenticated peer and learn the raw endpoint first.
	native.read <- makeUDPIPv4(bridge.config.ClientAddress, remote, 25001, 53, []byte("start"))
	_ = core.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, source, err := core.ReadFromUDP(make([]byte, 1500))
	if err != nil {
		t.Fatal(err)
	}
	for _, packet := range [][]byte{first, second, icmp} {
		if !validIPv4(packet, DefaultMTU) {
			t.Fatal("invalid fragment/ICMP test fixture")
		}
		if _, err = core.WriteToUDP(packet, source); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-native.write:
			if !bytes.Equal(got, packet) {
				t.Fatal("fragment or ICMP packet was changed by the bridge")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("fragment or ICMP packet did not reach native peer")
		}
	}
}
