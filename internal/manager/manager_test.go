package manager

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RATOR2000/csqtt-entware/internal/wgbridge"
)

func TestProfileUsesAssignedAddressAndPreservesIdentityOnChange(t *testing.T) {
	m := newTestManager(t)
	if _, err := m.Profile(); err == nil {
		t.Fatal("exported a profile before the server allocated an address")
	}
	m.core = coreStatus{State: "connected", ActiveWorkers: 9, TunnelIP: "11.8.0.2"}
	first, err := m.Profile()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(first, "Address = 11.8.0.2/32") || !strings.Contains(first, "Endpoint = 127.0.0.1:51820") || !strings.Contains(first, "MTU = 1280") {
		t.Fatal("generated profile does not match the actual local bridge")
	}
	if strings.Contains(first, m.settings.ServerPrivateKey) {
		t.Fatal("profile leaked the server private key")
	}
	serverKey, clientKey := m.settings.ServerPrivateKey, m.settings.ClientPrivateKey
	m.core.TunnelIP = "11.8.0.3"
	m.lastError = "profile_reimport_required"
	second, err := m.Profile()
	if err != nil || !strings.Contains(second, "Address = 11.8.0.3/32") {
		t.Fatal("could not regenerate the profile after an address change")
	}
	if m.settings.ServerPrivateKey != serverKey || m.settings.ClientPrivateKey != clientKey || m.settings.ProfileAddress != "11.8.0.3" || m.lastError != "" {
		t.Fatal("profile regeneration rotated identity or retained stale state")
	}
}

func TestRunAndCloseAreSerializedAndCannotResurrectClosedManager(t *testing.T) {
	for i := 0; i < 30; i++ {
		m := newTestManager(t)
		var workers sync.WaitGroup
		workers.Add(2)
		go func() { defer workers.Done(); m.Run(context.Background()) }()
		go func() { defer workers.Done(); m.Close() }()
		done := make(chan struct{})
		go func() { workers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("Run/Close left a manager goroutine blocked")
		}
		m.Run(context.Background())
		if !m.closed || m.cmd != nil || m.bridge != nil {
			t.Fatal("closed manager was restarted")
		}
	}
}

func TestConnectAfterCloseCannotPersistAnEnabledIntent(t *testing.T) {
	m := newTestManager(t)
	if err := m.Save(testCredentials()); err != nil {
		t.Fatal(err)
	}
	m.Close()
	if err := m.Connect(); err == nil {
		t.Fatal("closed manager accepted a connect request")
	}
	settings, err := loadSettings(m.opts.ConfigPath)
	if err != nil || settings.Enabled || m.settings.Enabled {
		t.Fatal("failed shutdown-racing connect persisted an enabled intent")
	}
}

func freeManagerUDP(t *testing.T) string {
	t.Helper()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	address := socket.LocalAddr().String()
	_ = socket.Close()
	return address
}

func TestDisconnectStopsBridgeEvenWhenSettingsCannotBeSaved(t *testing.T) {
	m := newTestManager(t)
	peer, err := wgbridge.PublicKey(m.settings.ClientPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	bridge, err := wgbridge.New(wgbridge.Config{PrivateKey: m.settings.ServerPrivateKey, PeerPublicKey: peer, ClientAddress: netip.MustParseAddr("11.8.0.2"), EncryptedListenAddress: freeManagerUDP(t), CoreAddress: freeManagerUDP(t), PacketListenAddress: freeManagerUDP(t)})
	if err != nil {
		t.Fatal(err)
	}
	if err = bridge.Start(); err != nil {
		t.Fatal(err)
	}
	m.bridge, m.bridgeIP, m.settings.Enabled = bridge, "11.8.0.2", true
	// A directory cannot be atomically replaced with the private settings file.
	m.opts.ConfigPath = m.opts.RuntimeDir
	if err = m.Disconnect(); err == nil {
		t.Fatal("failed save was not reported")
	}
	if m.bridge != nil || bridge.Status().Running || m.settings.Enabled {
		t.Fatal("stop left the packet bridge active after a persistence failure")
	}
}

func TestStopClearsReadinessAndRestartsNoLongerRequested(t *testing.T) {
	m := newTestManager(t)
	m.settings.Enabled = true
	m.core = coreStatus{State: "connected", ActiveWorkers: 9, TunnelIP: "11.8.0.2", Generation: 42}
	m.generation = 42
	m.probe = ProbeStatus{State: "ok", CheckedAt: time.Now(), Milliseconds: 12}
	if err := m.Disconnect(); err != nil {
		t.Fatal(err)
	}
	status := m.Snapshot()
	if status.Enabled || status.CoreReady || status.ProfileReady || status.WireGuard.Running || status.Probe.State != "not_checked" || m.generation != 0 {
		t.Fatalf("stop retained stale readiness: %+v", status)
	}
	settings, err := loadSettings(m.opts.ConfigPath)
	if err != nil || settings.Enabled {
		t.Fatal("stop intent was not persisted")
	}
}

func TestFailedSaveDoesNotChangeActiveSettings(t *testing.T) {
	m := newTestManager(t)
	if err := m.Save(testCredentials()); err != nil {
		t.Fatal(err)
	}
	before := m.settings
	m.opts.ConfigPath = filepath.Join(m.opts.RuntimeDir, "directory")
	if err := os.Mkdir(m.opts.ConfigPath, 0700); err != nil {
		t.Fatal(err)
	}
	input := testCredentials()
	input.Password = "replacement-test-password"
	if err := m.Save(input); err == nil {
		t.Fatal("accepted a failed settings write")
	}
	if m.settings != before {
		t.Fatal("failed persistence changed the in-memory configuration")
	}
}
