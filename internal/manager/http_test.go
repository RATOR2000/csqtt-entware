package manager

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	directory := t.TempDir()
	m, err := New(Options{Listen: "127.0.0.1:8080", ConfigPath: filepath.Join(directory, "config", "settings.json"), RuntimeDir: filepath.Join(directory, "run"), CorePath: filepath.Join(directory, "core-not-installed")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	return m
}

func apiRequest(m *Manager, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "http://127.0.0.1:8080"+path, strings.NewReader(body))
	for key, value := range headers {
		if key == "Host" {
			request.Host = value
		} else {
			request.Header.Set(key, value)
		}
	}
	response := httptest.NewRecorder()
	m.Handler().ServeHTTP(response, request)
	return response
}

func TestHTTPRejectsCrossSiteAndRebindingRequests(t *testing.T) {
	m := newTestManager(t)
	tests := []struct {
		name, method, path string
		headers            map[string]string
	}{
		{"foreign host", "GET", "/api/session", map[string]string{"Host": "attacker.example:8080"}},
		{"host without port", "GET", "/api/session", map[string]string{"Host": "127.0.0.1"}},
		{"wrong authority port", "GET", "/api/session", map[string]string{"Host": "127.0.0.1:8081"}},
		{"foreign origin", "GET", "/api/session", map[string]string{"Origin": "http://attacker.example"}},
		{"origin userinfo", "GET", "/api/session", map[string]string{"Origin": "http://user@127.0.0.1:8080"}},
		{"origin query", "GET", "/api/session", map[string]string{"Origin": "http://127.0.0.1:8080?unexpected=1"}},
		{"origin fragment", "GET", "/api/session", map[string]string{"Origin": "http://127.0.0.1:8080#unexpected"}},
		{"cross site metadata", "GET", "/api/status", map[string]string{"Sec-Fetch-Site": "cross-site"}},
		{"same site is insufficient", "GET", "/api/status", map[string]string{"Sec-Fetch-Site": "same-site"}},
		{"missing mutation token", "POST", "/api/disconnect", map[string]string{"Content-Type": "application/json"}},
		{"wrong mutation token", "POST", "/api/disconnect", map[string]string{"Content-Type": "application/json", "X-CSRF-Token": "wrong"}},
		{"private profile needs token", "GET", "/api/wireguard.conf", nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := apiRequest(m, test.method, test.path, "{}", test.headers)
			if response.Code != http.StatusForbidden {
				t.Fatalf("request admitted: status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestSessionAndSecurityHeaders(t *testing.T) {
	m := newTestManager(t)
	response := apiRequest(m, "GET", "/api/session", "", map[string]string{"Origin": "http://127.0.0.1:8080", "Sec-Fetch-Site": "same-origin"})
	if response.Code != 200 {
		t.Fatalf("same-origin session failed: %s", response.Body.String())
	}
	var session struct {
		CSRF string `json:"csrf"`
	}
	if json.Unmarshal(response.Body.Bytes(), &session) != nil || len(session.CSRF) != 64 || session.CSRF != m.token {
		t.Fatal("missing unpredictable session token")
	}
	for key, value := range map[string]string{"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"} {
		if response.Header().Get(key) != value {
			t.Fatalf("missing security header %s", key)
		}
	}
	if !strings.Contains(response.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatal("panel can be framed")
	}
	if response.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("session endpoint must not expose a CORS token")
	}
}

func TestOnlyConfiguredAuthorityAndDocumentedSSHTunnelAreAccepted(t *testing.T) {
	m := newTestManager(t)
	for _, host := range []string{m.opts.Listen, "127.0.0.1:18080", "localhost:18080"} {
		response := apiRequest(m, "GET", "/api/session", "", map[string]string{"Host": host, "Origin": "http://" + host})
		if response.Code != 200 {
			t.Fatalf("documented panel authority rejected: %q", host)
		}
	}
	for _, host := range []string{"127.0.0.1:80", "localhost:8080", "localhost:18081", "192.168.99.1:18080"} {
		response := apiRequest(m, "GET", "/api/session", "", map[string]string{"Host": host})
		if response.Code != http.StatusForbidden {
			t.Fatalf("unexpected panel authority accepted: %q", host)
		}
	}
}

func testCredentials() SettingsInput {
	return SettingsInput{Peer: "vpn.example:443", Password: "private-test-password-4f35", VKLink: "https://vk.com/call/join/private-test-vk-61a9", DNS: "9.9.9.9"}
}

func TestCredentialRedactionAndBlankFieldPreservation(t *testing.T) {
	m := newTestManager(t)
	credentials := testCredentials()
	if err := m.Save(credentials); err != nil {
		t.Fatal(err)
	}
	if err := m.Save(SettingsInput{Peer: credentials.Peer, DNS: "149.112.112.112"}); err != nil {
		t.Fatal(err)
	}
	if m.settings.Password != credentials.Password || m.settings.VKLink != credentials.VKLink {
		t.Fatal("blank web fields erased stored credentials")
	}
	secrets := []string{credentials.Password, credentials.VKLink, m.settings.ServerPrivateKey, m.settings.ClientPrivateKey}
	for _, path := range []string{"/api/settings", "/api/status", "/api/session"} {
		response := apiRequest(m, "GET", path, "", nil)
		if response.Code != 200 {
			t.Fatalf("%s failed: %d", path, response.Code)
		}
		for _, secret := range secrets {
			if strings.Contains(response.Body.String(), secret) {
				t.Fatalf("%s returned a private field", path)
			}
		}
	}
	body, _ := json.Marshal(SettingsInput{Peer: "bad", Password: credentials.Password, VKLink: credentials.VKLink})
	response := apiRequest(m, "POST", "/api/settings", string(body), map[string]string{"X-CSRF-Token": m.token, "Content-Type": "application/json"})
	if response.Code != 400 || strings.Contains(response.Body.String(), credentials.Password) || strings.Contains(response.Body.String(), credentials.VKLink) {
		t.Fatal("validation error exposed credentials")
	}
}

func TestMutationBodyBoundaries(t *testing.T) {
	m := newTestManager(t)
	for _, test := range []struct {
		name, contentType, body string
		want                    int
	}{
		{"form", "application/x-www-form-urlencoded", "enabled=false", 415},
		{"unknown field", "application/json", `{"unknown":true}`, 400},
		{"two objects", "application/json", `{} {}`, 400},
		{"oversized", "application/json", `{"peer":"` + strings.Repeat("a", 17000) + `"}`, 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := apiRequest(m, "POST", "/api/settings", test.body, map[string]string{"X-CSRF-Token": m.token, "Content-Type": test.contentType})
			if response.Code != test.want {
				t.Fatalf("status=%d want=%d body=%s", response.Code, test.want, response.Body.String())
			}
		})
	}
}
