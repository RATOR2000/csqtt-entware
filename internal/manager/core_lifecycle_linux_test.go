//go:build linux

package manager

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func requireActivationHost(t *testing.T) {
	t.Helper()
	if err := checkIPv4Only(); err != nil {
		t.Skip("activation correctly refuses this IPv6-enabled host; lifecycle fixture requires IPv4")
	}
}

func coreFixture(t *testing.T, script string) (*Manager, string) {
	t.Helper()
	requireActivationHost(t)
	m := newTestManager(t)
	if err := m.Save(testCredentials()); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "fake-core")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	m.opts.CorePath = path
	return m, dir
}

func awaitCoreExit(t *testing.T, m *Manager) {
	t.Helper()
	select {
	case <-m.done:
	case <-time.After(2 * time.Second):
		t.Fatal("core fixture did not exit")
	}
}

func TestCoreLifecycleKeepsCredentialsOutOfArgumentsAndStopsOwnedProcess(t *testing.T) {
	m, _ := coreFixture(t, "exec sleep 30")
	if err := m.startCoreLocked(false); err != nil {
		t.Fatal(err)
	}
	arguments := strings.Join(m.cmd.Args, " ")
	for _, secret := range []string{m.settings.Password, m.settings.VKLink, m.settings.ServerPrivateKey, m.settings.ClientPrivateKey} {
		if strings.Contains(arguments, secret) {
			t.Fatal("spawned core exposes credentials in process arguments")
		}
	}
	if len(m.cmd.Args) != 3 || m.cmd.Args[1] != "--config-file" {
		t.Fatal("core did not receive the private configuration interface")
	}
	info, err := os.Stat(m.cmd.Args[2])
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("core private configuration is not mode 0600: %v", err)
	}
	done := m.done
	if err := m.Disconnect(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	default:
		t.Fatal("disconnect returned before reaping its core")
	}
	if m.cmd != nil || m.done != nil || m.settings.Enabled {
		t.Fatal("disconnect retained ownership or enabled intent")
	}
	m.tick(context.Background())
	if m.cmd != nil {
		t.Fatal("monitor restarted a core after explicit disconnect")
	}
}

func TestFailedExecAndExitedCoreConsumeBoundedRestartBudget(t *testing.T) {
	m, _ := coreFixture(t, "exit 17")
	for i := 0; i < 3; i++ {
		if err := m.startCoreLocked(false); err != nil {
			t.Fatal(err)
		}
		awaitCoreExit(t, m)
		m.stopCoreLocked()
	}
	if err := m.startCoreLocked(false); err == nil || m.lastError != "restart_budget_exhausted" || m.cmd != nil {
		t.Fatal("crashed cores were restarted beyond the budget")
	}
	if err := m.startCoreLocked(true); err != nil || len(m.attempts) != 1 {
		t.Fatal("explicit user retry did not reset the restart budget")
	}
	awaitCoreExit(t, m)
	m.stopCoreLocked()
	if err := os.Chmod(m.opts.CorePath, 0600); err != nil {
		t.Fatal(err)
	}
	m.attempts = nil
	for i := 0; i < 3; i++ {
		if err := m.startCoreLocked(false); err == nil || m.lastError != "core_start_failed" {
			t.Fatal("nonexecutable core did not fail safely")
		}
	}
	if err := m.startCoreLocked(false); err == nil || m.lastError != "restart_budget_exhausted" {
		t.Fatal("failed exec attempts did not consume the restart budget")
	}
}

func TestKnownStartupFailureSurvivesRestartBudgetWithoutLeakingOutput(t *testing.T) {
	for _, fixture := range []struct{ line, code string }{
		{"[DAEMON] configuration_failed: invalid VK call hash", "core_config_vk_invalid"},
		{"[PANIC] Rust client task failed", "core_runtime_panic"},
		{"unknown private-test-secret https://example.invalid/private-call", "core_exited"},
	} {
		t.Run(fixture.code, func(t *testing.T) {
			m, _ := coreFixture(t, "printf '%s\\n' '"+fixture.line+"' >&2; exit 1")
			m.settings.Enabled = true
			for i := 0; i < 3; i++ {
				if err := m.startCoreLocked(false); err != nil {
					t.Fatal(err)
				}
				awaitCoreExit(t, m)
				m.tick(context.Background())
				if m.Snapshot().Error != fixture.code {
					t.Fatal("core startup output did not become the expected public enum")
				}
			}
			m.lastStart = time.Now().Add(-16 * time.Second)
			m.tick(context.Background())
			want := fixture.code
			if want == "core_exited" {
				want = "restart_budget_exhausted"
			}
			if m.cmd != nil || m.Snapshot().Error != want {
				t.Fatal("restart budget discarded the recognized startup cause or started another core")
			}
		})
	}
}

func TestStaleStatusAndChangedAllocationCloseRealPacketBridge(t *testing.T) {
	m, _ := coreFixture(t, "exec sleep 30")
	if err := m.startCoreLocked(false); err != nil {
		t.Fatal(err)
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	status := coreStatus{SchemaVersion: 1, State: "connected", PID: m.cmd.Process.Pid,
		ProcessStartticks: procStartTicks(m.cmd.Process.Pid), BootID: strings.TrimSpace(string(boot)),
		UpdatedBoottimeMS: bootTimeMS(), Generation: 7, PacketAdapter: "udp", TunnelIP: "11.8.0.2", ActiveWorkers: 9}
	path := filepath.Join(m.opts.RuntimeDir, "status.json")
	if err = atomicJSON(path, status); err != nil {
		t.Fatal(err)
	}
	m.lastProbe = time.Now() // No real DNS endpoint belongs to this fixture.
	m.tick(context.Background())
	if m.bridge == nil || !m.bridge.Status().Running {
		t.Fatal("fresh core status did not activate the packet bridge")
	}
	first := m.bridge
	m.settings.ProfileAddress = "11.8.0.3"
	m.tick(context.Background())
	if m.bridge != nil || first.Status().Running || m.lastError != "profile_reimport_required" {
		t.Fatal("an allocation mismatch continued forwarding with the old profile")
	}
	m.settings.ProfileAddress = status.TunnelIP
	m.lastProbe = time.Now()
	m.tick(context.Background())
	if m.bridge == nil {
		t.Fatal("bridge could not resume after the matching profile was acknowledged")
	}
	second := m.bridge
	status.UpdatedBoottimeMS = bootTimeMS() - 13000
	if err = atomicJSON(path, status); err != nil {
		t.Fatal(err)
	}
	m.tick(context.Background())
	if m.bridge != nil || second.Status().Running || m.Snapshot().CoreReady || m.Snapshot().ProfileReady {
		t.Fatal("stale core status retained forwarding or readiness")
	}
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 39001})
	if err != nil {
		t.Fatal("closed bridge retained its raw packet listener")
	}
	_ = socket.Close()
}
