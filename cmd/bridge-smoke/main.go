// bridge-smoke is an isolated developer fixture. It never connects to a CSQTT
// server or changes router routes/policies. Its private profile is disposable.
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/RATOR2000/csqtt-entware/internal/wgbridge"
)

func sum(data []byte) uint16 {
	var n uint32
	for len(data) > 1 {
		n += uint32(binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	if len(data) > 0 {
		n += uint32(data[0]) << 8
	}
	for n>>16 != 0 {
		n = n&65535 + n>>16
	}
	return ^uint16(n)
}
func echo(packet []byte) []byte {
	if len(packet) < 28 || packet[0]>>4 != 4 || packet[9] != 1 {
		return nil
	}
	h := int(packet[0]&15) * 4
	if h < 20 || len(packet) < h+8 || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) || packet[h] != 8 || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
		return nil
	}
	out := append([]byte(nil), packet...)
	copy(out[12:16], packet[16:20])
	copy(out[16:20], packet[12:16])
	out[8] = 64
	out[h] = 0
	out[h+2] = 0
	out[h+3] = 0
	binary.BigEndian.PutUint16(out[h+2:h+4], sum(out[h:]))
	out[10] = 0
	out[11] = 0
	binary.BigEndian.PutUint16(out[10:12], sum(out[:h]))
	return out
}
func main() {
	runtime.GOMAXPROCS(1)
	debug.SetMemoryLimit(16 << 20)
	dir := flag.String("dir", "/opt/var/run/csqtt-smoke", "Private fixture directory")
	flag.Parse()
	if err := os.MkdirAll(*dir, 0700); err != nil {
		panic("private fixture directory unavailable")
	}
	server, e := wgbridge.GenerateKeys()
	if e != nil {
		panic(e)
	}
	client, e := wgbridge.GenerateKeys()
	if e != nil {
		panic(e)
	}
	address := netip.MustParseAddr("10.66.67.254")
	profile, e := wgbridge.GenerateClientConfig(wgbridge.ClientProfile{PrivateKey: client.PrivateKey, ServerPublicKey: server.PublicKey, Address: address, Endpoint: "127.0.0.1:51821", MTU: 1280})
	if e != nil {
		panic(e)
	}
	if os.WriteFile(filepath.Join(*dir, "profile.conf"), []byte(profile), 0600) != nil {
		panic("private profile unavailable")
	}
	core, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 39010})
	if e != nil {
		panic(e)
	}
	defer core.Close()
	bridge, e := wgbridge.New(wgbridge.Config{PrivateKey: server.PrivateKey, PeerPublicKey: client.PublicKey, ClientAddress: address, EncryptedListenAddress: "127.0.0.1:51821", CoreAddress: "127.0.0.1:39010", PacketListenAddress: "127.0.0.1:39011", MTU: 1280})
	if e != nil {
		panic(e)
	}
	if e = bridge.Start(); e != nil {
		panic(e)
	}
	defer bridge.Stop()
	go func() {
		var buffer [2049]byte
		for {
			n, peer, err := core.ReadFromUDPAddrPort(buffer[:])
			if err != nil {
				return
			}
			if peer != netip.MustParseAddrPort("127.0.0.1:39011") {
				continue
			}
			if reply := echo(buffer[:n]); reply != nil {
				_, _ = core.WriteToUDPAddrPort(reply, peer)
			}
		}
	}()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	fmt.Println("Isolated WireGuard ICMP fixture ready; no Internet connectivity is provided")
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			data, _ := json.Marshal(bridge.Status())
			path := filepath.Join(*dir, "status.json")
			if os.WriteFile(path+".new", data, 0600) == nil {
				_ = os.Rename(path+".new", path)
			}
		}
	}
}
