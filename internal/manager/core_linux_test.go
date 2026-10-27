//go:build linux

package manager

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCoreStatusRejectsStaleProcessBootAndGeneration(t *testing.T) {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Skip("Linux /proc is required")
	}
	m := &Manager{opts: Options{RuntimeDir: t.TempDir()}, cmd: &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}}
	now := bootTimeMS()
	valid := coreStatus{SchemaVersion: 1, State: "connected", PID: os.Getpid(), ProcessStartticks: procStartTicks(os.Getpid()), BootID: strings.TrimSpace(string(boot)), UpdatedBoottimeMS: now, Generation: 123, PacketAdapter: "udp", TunnelIP: "11.8.0.2", ActiveWorkers: 9}
	path := filepath.Join(m.opts.RuntimeDir, "status.json")
	if err = atomicJSON(path, valid); err != nil {
		t.Fatal(err)
	}
	if _, fresh := m.readCoreLocked(); !fresh || m.generation != valid.Generation {
		t.Fatal("rejected current process identity")
	}
	for _, test := range []struct {
		name   string
		change func(*coreStatus)
	}{
		{"schema", func(s *coreStatus) { s.SchemaVersion = 2 }},
		{"pid", func(s *coreStatus) { s.PID++ }},
		{"start ticks", func(s *coreStatus) { s.ProcessStartticks++ }},
		{"boot", func(s *coreStatus) { s.BootID = "another-boot" }},
		{"generation", func(s *coreStatus) { s.Generation++ }},
		{"zero generation", func(s *coreStatus) { s.Generation = 0 }},
		{"packet backend", func(s *coreStatus) { s.PacketAdapter = "tun" }},
		{"future", func(s *coreStatus) { s.UpdatedBoottimeMS = now + 5000 }},
		{"stale", func(s *coreStatus) { s.UpdatedBoottimeMS = now - 13000 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			status := valid
			test.change(&status)
			if err := atomicJSON(path, status); err != nil {
				t.Fatal(err)
			}
			if _, fresh := m.readCoreLocked(); fresh {
				t.Fatal("accepted stale or mismatched status")
			}
		})
	}
}

func TestCoreStatusRejectsTrailingJSONAndReadableFiles(t *testing.T) {
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Skip("Linux /proc is required")
	}
	m := &Manager{opts: Options{RuntimeDir: t.TempDir()}, cmd: &exec.Cmd{Process: &os.Process{Pid: os.Getpid()}}}
	s := coreStatus{SchemaVersion: 1, PID: os.Getpid(), ProcessStartticks: procStartTicks(os.Getpid()), BootID: strings.TrimSpace(string(boot)), UpdatedBoottimeMS: bootTimeMS(), Generation: 123, PacketAdapter: "udp"}
	path := filepath.Join(m.opts.RuntimeDir, "status.json")
	if err = atomicJSON(path, s); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(" {}")
	_ = f.Close()
	if _, fresh := m.readCoreLocked(); fresh {
		t.Fatal("accepted a status with trailing JSON")
	}
	if err = atomicJSON(path, s); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, fresh := m.readCoreLocked(); fresh {
		t.Fatal("accepted an insecurely readable runtime status file")
	}
}
