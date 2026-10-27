// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package manager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/RATOR2000/csqtt-entware/internal/captcha"
	"github.com/RATOR2000/csqtt-entware/internal/wgbridge"
)

type Options struct{ Listen, ConfigPath, RuntimeDir, CorePath string }
type coreStatus struct {
	SchemaVersion     int      `json:"schema_version"`
	State             string   `json:"state"`
	PID               int      `json:"pid"`
	ProcessStartticks uint64   `json:"process_startticks"`
	BootID            string   `json:"boot_id"`
	UpdatedBoottimeMS uint64   `json:"updated_boottime_ms"`
	Generation        uint64   `json:"generation"`
	PacketAdapter     string   `json:"packet_adapter"`
	TunnelIP          string   `json:"tunnel_ip"`
	DNS               []string `json:"dns"`
	ActiveWorkers     int      `json:"active_workers"`
	BytesUp           int64    `json:"bytes_up"`
	BytesDown         int64    `json:"bytes_down"`
	Captcha           *struct {
		State     string `json:"state"`
		ExpiresAt int64  `json:"expires_at"`
	} `json:"captcha"`
}
type ProbeStatus struct {
	State        string    `json:"state"`
	CheckedAt    time.Time `json:"checked_at"`
	Milliseconds int64     `json:"milliseconds"`
}
type PublicStatus struct {
	State                   string          `json:"state"`
	Enabled                 bool            `json:"enabled"`
	Configured              bool            `json:"configured"`
	CoreReady               bool            `json:"core_ready"`
	CoreInstalled           bool            `json:"core_installed"`
	ProfileReady            bool            `json:"profile_ready"`
	ProfileReimportRequired bool            `json:"profile_reimport_required"`
	TunnelIP                string          `json:"tunnel_ip,omitempty"`
	Workers                 int             `json:"workers"`
	BytesUp                 int64           `json:"bytes_up"`
	BytesDown               int64           `json:"bytes_down"`
	CaptchaRequired         bool            `json:"captcha_required"`
	WireGuard               wgbridge.Status `json:"wireguard"`
	Probe                   ProbeStatus     `json:"probe"`
	MemAvailableKB          uint64          `json:"mem_available_kb"`
	Error                   string          `json:"error,omitempty"`
}
type Manager struct {
	op         sync.Mutex
	opts       Options
	settings   Settings
	token      string
	host       string
	cmd        *exec.Cmd
	done       chan struct{}
	generation uint64
	core       coreStatus
	bridge     *wgbridge.Bridge
	bridgeIP   string
	probe      ProbeStatus
	lastError  string
	lastProbe  time.Time
	attempts   []time.Time
	lastStart  time.Time
	helper     *captcha.Service
	cancel     context.CancelFunc
	closed     bool
}

func New(opts Options) (*Manager, error) {
	host, port, err := net.SplitHostPort(opts.Listen)
	ip, e := netip.ParseAddr(host)
	p, pe := strconv.Atoi(port)
	if err != nil || e != nil || pe != nil || !ip.Is4() || (!ip.IsPrivate() && !ip.IsLoopback()) || p < 1 || p > 65535 {
		return nil, errors.New("listen_requires_exact_lan_or_loopback_ipv4")
	}
	if err = os.MkdirAll(opts.RuntimeDir, 0700); err != nil {
		return nil, err
	}
	if err = os.Chmod(opts.RuntimeDir, 0700); err != nil {
		return nil, err
	}
	settings, err := loadSettings(opts.ConfigPath)
	if err != nil {
		return nil, err
	}
	token, err := randomToken()
	if err != nil {
		return nil, err
	}
	m := &Manager{opts: opts, settings: settings, token: token, host: host, probe: ProbeStatus{State: "not_checked"}}
	m.helper = captcha.NewService(host, filepath.Join(filepath.Dir(opts.ConfigPath), "captcha"), filepath.Join(opts.RuntimeDir, "control.sock"))
	return m, nil
}

func (m *Manager) Run(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	m.op.Lock()
	if m.closed || m.cancel != nil {
		m.op.Unlock()
		return
	}
	m.cancel = cancel
	if m.settings.Enabled {
		_ = m.startCoreLocked(false)
	}
	m.op.Unlock()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			m.Close()
			return
		case <-ticker.C:
			m.tick(ctx)
		}
	}
}

func (m *Manager) Close() {
	m.op.Lock()
	defer m.op.Unlock()
	m.closed = true
	if m.cancel != nil {
		m.cancel()
	}
	m.stopCoreLocked()
}

func memAvailableKB() uint64 {
	data, _ := os.ReadFile("/proc/meminfo")
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) > 1 && f[0] == "MemAvailable:" {
			n, _ := strconv.ParseUint(f[1], 10, 64)
			return n
		}
	}
	return 0
}

func (m *Manager) startCoreLocked(resetBudget bool) error {
	if m.closed {
		return errors.New("Менеджер CSQTT завершает работу")
	}
	if m.cmd != nil {
		return nil
	}
	if resetBudget {
		m.attempts = nil
	}
	if err := validateCredentials(m.settings); err != nil {
		return err
	}
	if err := checkIPv4Only(); err != nil {
		m.lastError = "ipv6_bypass_detected"
		return err
	}
	if mem := memAvailableKB(); mem > 0 && mem < 16384 {
		m.lastError = "low_memory"
		return errors.New("Недостаточно свободной памяти")
	}
	if info, err := os.Stat(m.opts.CorePath); err != nil || !info.Mode().IsRegular() {
		m.lastError = "core_not_installed"
		return errors.New("Ядро CSQTT ещё не установлено")
	}
	now := time.Now()
	recent := m.attempts[:0]
	for _, t := range m.attempts {
		if now.Sub(t) < 10*time.Minute {
			recent = append(recent, t)
		}
	}
	m.attempts = recent
	if len(m.attempts) >= 3 {
		m.lastError = "restart_budget_exhausted"
		return errors.New("Остановлено после трёх неудачных запусков. Проверьте диагностику")
	}
	conf := map[string]any{"peer": m.settings.Peer, "password": m.settings.Password, "vk_hashes": []string{m.settings.VKLink}, "workers": 9, "packet_adapter": "udp", "packet_listen": "127.0.0.1:39000", "packet_peer": "127.0.0.1:39001", "status_file": filepath.Join(m.opts.RuntimeDir, "status.json"), "control_socket": filepath.Join(m.opts.RuntimeDir, "control.sock"), "identity_file": filepath.Join(filepath.Dir(m.opts.ConfigPath), "identity.json")}
	path := filepath.Join(m.opts.RuntimeDir, "client.json")
	if err := atomicJSON(path, conf); err != nil {
		m.lastError = "private_config_failed"
		return errors.New("Не удалось сохранить закрытую конфигурацию")
	}
	// Delete only this manager's previous status. Ownership is checked again on read.
	_ = os.Remove(filepath.Join(m.opts.RuntimeDir, "status.json"))
	cmd := exec.Command(m.opts.CorePath, "--config-file", path)
	setupProcess(cmd)
	m.lastStart = now
	m.attempts = append(m.attempts, now)
	// Core output is deliberately not forwarded: no upstream error text can expose
	// credentials or VK URLs in syslog, the terminal, or a public API response.
	if err := cmd.Start(); err != nil {
		m.lastError = "core_start_failed"
		return errors.New("Не удалось запустить ядро CSQTT")
	}
	m.cmd = cmd
	m.done = make(chan struct{})
	m.generation = 0
	m.core = coreStatus{}
	m.lastError = ""
	done := m.done
	go func() { _ = cmd.Wait(); close(done) }()
	return nil
}

func (m *Manager) stopBridgeLocked() {
	if m.bridge != nil {
		_ = m.bridge.Stop()
		m.bridge = nil
	}
	m.bridgeIP = ""
	m.probe = ProbeStatus{State: "not_checked"}
	m.lastProbe = time.Time{}
}
func (m *Manager) stopCoreLocked() {
	m.stopBridgeLocked()
	m.helper.Stop()
	if m.cmd != nil {
		_ = m.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-m.done:
		case <-time.After(10 * time.Second):
			_ = m.cmd.Process.Kill()
			<-m.done
		}
		m.cmd = nil
		m.done = nil
	}
	m.generation = 0
	m.core = coreStatus{}
}

func procStartTicks(pid int) uint64 {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	i := strings.LastIndexByte(string(raw), ')')
	if i < 0 {
		return 0
	}
	f := strings.Fields(string(raw)[i+1:])
	if len(f) <= 19 {
		return 0
	}
	n, _ := strconv.ParseUint(f[19], 10, 64)
	return n
}
func bootTimeMS() uint64 {
	raw, _ := os.ReadFile("/proc/uptime")
	f := strings.Fields(string(raw))
	if len(f) == 0 {
		return 0
	}
	n, _ := strconv.ParseFloat(f[0], 64)
	return uint64(n * 1000)
}

func (m *Manager) readCoreLocked() (coreStatus, bool) {
	var s coreStatus
	if m.cmd == nil {
		return s, false
	}
	if privatePath(filepath.Join(m.opts.RuntimeDir, "status.json")) != nil {
		return s, false
	}
	f, err := os.Open(filepath.Join(m.opts.RuntimeDir, "status.json"))
	if err != nil {
		return s, false
	}
	defer f.Close()
	data, readErr := io.ReadAll(io.LimitReader(f, 65537))
	if readErr != nil || len(data) > 65536 {
		return s, false
	}
	d := json.NewDecoder(strings.NewReader(string(data)))
	if d.Decode(&s) != nil || d.Decode(&struct{}{}) != io.EOF {
		return s, false
	}
	boot, _ := os.ReadFile("/proc/sys/kernel/random/boot_id")
	ticks := procStartTicks(m.cmd.Process.Pid)
	now := bootTimeMS()
	if s.SchemaVersion != 1 || s.PID != m.cmd.Process.Pid || s.PacketAdapter != "udp" || s.Generation == 0 || ticks == 0 || s.ProcessStartticks != ticks || s.BootID != strings.TrimSpace(string(boot)) || s.UpdatedBoottimeMS > now+1000 || now > s.UpdatedBoottimeMS+12000 {
		return coreStatus{}, false
	}
	if m.generation == 0 {
		m.generation = s.Generation
	}
	if s.Generation != m.generation {
		return coreStatus{}, false
	}
	return s, true
}

func (m *Manager) tick(ctx context.Context) {
	m.op.Lock()
	if m.cmd != nil {
		select {
		case <-m.done:
			m.stopBridgeLocked()
			m.cmd = nil
			m.done = nil
			m.core = coreStatus{}
			m.lastError = "core_exited"
		default:
		}
	}
	if m.cmd == nil && m.settings.Enabled && time.Since(m.lastStart) > 15*time.Second {
		_ = m.startCoreLocked(false)
	}
	s, fresh := m.readCoreLocked()
	m.core = s
	ready := fresh && s.State == "connected" && s.ActiveWorkers > 0
	ip, err := netip.ParseAddr(s.TunnelIP)
	if err != nil || !ip.Is4() {
		ready = false
	}
	if !ready {
		m.stopBridgeLocked()
		m.op.Unlock()
		return
	}
	if m.settings.ProfileAddress != "" && m.settings.ProfileAddress != s.TunnelIP {
		m.stopBridgeLocked()
		m.lastError = "profile_reimport_required"
		m.op.Unlock()
		return
	}
	if m.bridge != nil && (m.bridgeIP != s.TunnelIP || !m.bridge.Status().Running) {
		m.stopBridgeLocked()
	}
	if m.bridge == nil {
		peer, e := wgbridge.PublicKey(m.settings.ClientPrivateKey)
		if e == nil {
			var b *wgbridge.Bridge
			b, e = wgbridge.New(wgbridge.Config{PrivateKey: m.settings.ServerPrivateKey, PeerPublicKey: peer, ClientAddress: ip, EncryptedListenAddress: "127.0.0.1:51820", CoreAddress: "127.0.0.1:39000", PacketListenAddress: "127.0.0.1:39001", MTU: 1280})
			if e == nil {
				e = b.Start()
			}
			if e == nil {
				m.bridge = b
				m.bridgeIP = s.TunnelIP
				m.lastError = ""
			}
		}
		if e != nil {
			m.lastError = "bridge_start_failed"
			m.op.Unlock()
			return
		}
	}
	b := m.bridge
	probe := time.Since(m.lastProbe) >= 30*time.Second
	dns, _ := netip.ParseAddr(m.settings.DNS)
	if probe {
		m.lastProbe = time.Now()
		m.probe.State = "checking"
	}
	m.op.Unlock()
	if probe {
		pctx, cancel := context.WithTimeout(ctx, 4*time.Second)
		elapsed, e := b.ProbeDNS(pctx, dns)
		cancel()
		m.op.Lock()
		if m.bridge == b {
			state := "ok"
			if e != nil {
				state = "failed"
			}
			m.probe = ProbeStatus{State: state, CheckedAt: time.Now().UTC(), Milliseconds: elapsed.Milliseconds()}
		}
		m.op.Unlock()
	}
}

func (m *Manager) Snapshot() PublicStatus {
	m.op.Lock()
	defer m.op.Unlock()
	_, coreErr := os.Stat(m.opts.CorePath)
	s := PublicStatus{State: "stopped", Enabled: m.settings.Enabled, Configured: validateCredentials(m.settings) == nil, CoreInstalled: coreErr == nil, Probe: m.probe, MemAvailableKB: memAvailableKB(), Error: m.lastError}
	if m.cmd != nil {
		s.State = "connecting"
		if m.core.State != "" {
			s.State = m.core.State
		}
	}
	s.CoreReady = m.core.State == "connected" && m.core.ActiveWorkers > 0
	s.Workers = m.core.ActiveWorkers
	s.BytesUp = m.core.BytesUp
	s.BytesDown = m.core.BytesDown
	s.CaptchaRequired = m.core.Captcha != nil
	if m.bridge != nil {
		s.WireGuard = m.bridge.Status()
		s.TunnelIP = m.bridgeIP
	}
	s.ProfileReimportRequired = m.lastError == "profile_reimport_required"
	s.ProfileReady = s.CoreReady && (m.bridge != nil || s.ProfileReimportRequired)
	if s.ProfileReimportRequired {
		s.State = "profile_reimport_required"
		s.TunnelIP = m.core.TunnelIP
	}
	if !s.CoreInstalled {
		s.State = "core_not_installed"
	}
	return s
}

func (m *Manager) Connect() error {
	m.op.Lock()
	defer m.op.Unlock()
	if m.closed {
		return errors.New("Менеджер CSQTT завершает работу")
	}
	if err := validateCredentials(m.settings); err != nil {
		return err
	}
	old := m.settings.Enabled
	m.settings.Enabled = true
	if err := atomicJSON(m.opts.ConfigPath, m.settings); err != nil {
		m.settings.Enabled = old
		return errors.New("Не удалось сохранить настройки")
	}
	return m.startCoreLocked(true)
}
func (m *Manager) Disconnect() error {
	m.op.Lock()
	defer m.op.Unlock()
	m.settings.Enabled = false
	err := atomicJSON(m.opts.ConfigPath, m.settings)
	m.stopCoreLocked()
	m.lastError = ""
	if err != nil {
		m.lastError = "stop_persistence_failed"
		return errors.New("CSQTT остановлен, но сохранить отключение не удалось. Проверьте USB перед перезапуском")
	}
	return nil
}

type SettingsInput struct {
	Peer     string `json:"peer"`
	Password string `json:"password"`
	VKLink   string `json:"vk_link"`
	DNS      string `json:"dns"`
}

func (m *Manager) Save(in SettingsInput) error {
	m.op.Lock()
	defer m.op.Unlock()
	if m.cmd != nil {
		return errors.New("Остановите CSQTT перед изменением настроек")
	}
	next := m.settings
	next.Peer = strings.TrimSpace(in.Peer)
	if in.Password != "" {
		next.Password = in.Password
	}
	if in.VKLink != "" {
		next.VKLink = strings.TrimSpace(in.VKLink)
	}
	if in.DNS != "" {
		next.DNS = strings.TrimSpace(in.DNS)
	}
	if err := validateCredentials(next); err != nil {
		return err
	}
	if err := atomicJSON(m.opts.ConfigPath, next); err != nil {
		return errors.New("Не удалось сохранить настройки")
	}
	m.settings = next
	return nil
}

func (m *Manager) Profile() (string, error) {
	m.op.Lock()
	defer m.op.Unlock()
	if m.core.State != "connected" || m.core.ActiveWorkers < 1 {
		return "", errors.New("Сначала подключите CSQTT и дождитесь получения адреса")
	}
	ip, err := netip.ParseAddr(m.core.TunnelIP)
	if err != nil {
		return "", errors.New("Адрес CSQTT ещё не получен")
	}
	pub, err := wgbridge.PublicKey(m.settings.ServerPrivateKey)
	if err != nil {
		return "", err
	}
	dns, _ := netip.ParseAddr(m.settings.DNS)
	profile, err := wgbridge.GenerateClientConfig(wgbridge.ClientProfile{PrivateKey: m.settings.ClientPrivateKey, ServerPublicKey: pub, Address: ip, Endpoint: "127.0.0.1:51820", DNS: dns, MTU: 1280})
	if err != nil {
		return "", err
	}
	next := m.settings
	next.ProfileAddress = ip.String()
	if err = atomicJSON(m.opts.ConfigPath, next); err != nil {
		return "", errors.New("Не удалось сохранить адрес профиля")
	}
	m.settings = next
	m.lastError = ""
	return profile, nil
}

func (m *Manager) PairCaptcha() (map[string]any, error) {
	m.op.Lock()
	defer m.op.Unlock()
	return m.helper.Pair()
}
func (m *Manager) CancelCaptcha() { m.op.Lock(); defer m.op.Unlock(); m.helper.Stop() }
