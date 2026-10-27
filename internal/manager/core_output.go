// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package manager

import "sync"

const maxStartupOutput = 4096

// Only complete, exact messages emitted before the daemon status exists are
// recognized. Never retain or publish arbitrary core output, which may contain
// credentials, VK URLs, paths or server responses.
var coreStartupFailures = [...]struct{ line, code string }{
	{"[DAEMON] configuration_failed: peer must be a host and port", "core_config_peer_invalid"},
	{"[DAEMON] configuration_failed: password must be 4..128 bytes without control delimiters", "core_config_password_invalid"},
	{"[DAEMON] configuration_failed: provide 1..6 VK call hashes or links", "core_config_vk_invalid"},
	{"[DAEMON] configuration_failed: invalid VK call hash", "core_config_vk_invalid"},
	{"[DAEMON] configuration_failed: workers must be a multiple of 9 within the hash capacity", "core_config_workers_invalid"},
	{"[DAEMON] configuration_failed: packet endpoints must be distinct fixed IPv4 loopback ports", "core_config_internal_invalid"},
	{"[DAEMON] configuration_failed: invalid obfuscation mode", "core_config_internal_invalid"},
	{"[DAEMON] configuration_failed: invalid TURN transport", "core_config_internal_invalid"},
	{"[DAEMON] configuration_failed: daemon supports vkcalls or legacy authentication", "core_config_internal_invalid"},
	{"[DAEMON] configuration_failed: invalid browser fingerprint", "core_config_internal_invalid"},
	{"[DAEMON] configuration_failed: invalid client IDs", "core_config_internal_invalid"},
	{"[DAEMON] configuration_failed: invalid TURN override", "core_config_internal_invalid"},
	{"[DAEMON] configuration_failed: invalid CAPTCHA timeout", "core_config_internal_invalid"},
	{"[DAEMON] configuration_failed: invalid TUN interface name", "core_config_internal_invalid"},
	{"[DAEMON] configuration_failed: daemon paths must be absolute without parent components", "core_config_internal_invalid"},
	{"[DAEMON] configuration_failed: daemon paths must be distinct", "core_config_internal_invalid"},
	{"[DAEMON] configuration_failed: invalid persistent device identity", "core_config_internal_invalid"},
	{"[PANIC] Rust client task failed", "core_runtime_panic"},
}

type coreStartupOutput struct {
	mu         sync.Mutex
	inspected  int
	position   int
	candidates uint32
	code       string
}

func newCoreStartupOutput() *coreStartupOutput {
	return &coreStartupOutput{candidates: (1 << len(coreStartupFailures)) - 1}
}

func (o *coreStartupOutput) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, b := range p {
		if o.inspected >= maxStartupOutput || o.code != "" {
			break
		}
		o.inspected++
		if b == '\n' {
			for i, failure := range coreStartupFailures {
				if o.candidates&(1<<i) != 0 && o.position == len(failure.line) {
					o.code = failure.code
					break
				}
			}
			o.position = 0
			o.candidates = (1 << len(coreStartupFailures)) - 1
			continue
		}
		for i, failure := range coreStartupFailures {
			if o.candidates&(1<<i) != 0 && (o.position >= len(failure.line) || failure.line[o.position] != b) {
				o.candidates &^= 1 << i
			}
		}
		o.position++
	}
	// Keep draining after the inspection budget; a noisy child must not block
	// waiting for its output pipe. The matcher retains no output bytes.
	return len(p), nil
}

func (o *coreStartupOutput) errorCode() string {
	if o == nil {
		return ""
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.code
}

func isCoreStartupError(code string) bool {
	for _, failure := range coreStartupFailures {
		if failure.code == code {
			return true
		}
	}
	return false
}
