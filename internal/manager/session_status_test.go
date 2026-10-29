package manager

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

func TestSessionFailureStatusIsAllowlistedAndClearsOnReadiness(t *testing.T) {
	for _, test := range []struct {
		name, core, managerError, want string
	}{
		{"timeout", `{"health":{"last_session_error":"handshake_timeout"}}`, "", "server_handshake_timeout"},
		{"rejected", `{"health":{"last_session_error":"handshake_rejected"}}`, "", "server_handshake_rejected"},
		{"unknown is private", `{"health":{"last_session_error":"private-secret-value"}}`, "", ""},
		{"ready hides history", `{"state":"connected","active_workers":9,"health":{"last_session_error":"handshake_timeout"}}`, "", ""},
		{"captcha takes priority", `{"captcha":{"state":"manual"},"health":{"last_session_error":"handshake_timeout"}}`, "", ""},
		{"manager failure takes priority", `{"health":{"last_session_error":"handshake_timeout"}}`, "profile_reimport_required", "profile_reimport_required"},
	} {
		t.Run(test.name, func(t *testing.T) {
			m := newTestManager(t)
			if err := json.Unmarshal([]byte(test.core), &m.core); err != nil {
				t.Fatal(err)
			}
			// Snapshot only needs a non-nil command to represent an active attempt.
			m.cmd = &exec.Cmd{}
			defer func() { m.cmd = nil }()
			m.lastError = test.managerError
			status := m.Snapshot()
			if status.Error != test.want {
				t.Fatalf("wrong public error: %q", status.Error)
			}
			data, _ := json.Marshal(status)
			if strings.Contains(string(data), "private-secret-value") {
				t.Fatal("private core error leaked")
			}
		})
	}
}
