package captcha

import (
	"encoding/json"
	"net"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestDestinationRestrictions(t *testing.T) {
	for _, u := range []string{"https://id.vk.com/captcha", "https://api.vk.ru/method/captchaNotRobot.check", "https://st.okcdn.ru/a.js"} {
		if !allowedURL(u) {
			t.Fatalf("rejected %s", u)
		}
	}
	for _, u := range []string{"http://id.vk.com/captcha", "https://vk.com.evil.test/", "https://evilvk.com/", "https://vk.com@evil.test/", "https://user:pass@vk.com/", "https://127.0.0.1/", "https://id.vk.com:8443/", "https://id.vk.com./"} {
		if allowedURL(u) {
			t.Fatalf("allowed %s", u)
		}
	}
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.1.1", "100.64.0.1", "198.18.0.1", "::1", "fe80::1", "fc00::1", "224.0.0.1", "192.0.2.1"} {
		if publicIP(net.ParseIP(ip)) {
			t.Fatalf("public %s", ip)
		}
	}
	if !publicIP(net.ParseIP("1.1.1.1")) {
		t.Fatal("public resolver rejected")
	}
}
func newTestBroker() *broker {
	return &broker{host: "192.168.1.1", port: "9443", pin: strings.Repeat("a", 64), core: func(r object) (object, error) {
		if r["command"] == "captcha_get" {
			return object{"ok": true, "captcha": object{"id": "job1", "state": "manual", "redirect_uri": "https://id.vk.com/captcha", "expires_at": time.Now().Add(time.Minute).Unix()}}, nil
		}
		return object{"ok": true}, nil
	}}
}
func TestPairClaimAndResult(t *testing.T) {
	b := newTestBroker()
	pair, e := b.pair()
	if e != nil {
		t.Fatal(e)
	}
	uri, _ := url.Parse(pair["uri"].(string))
	grant := uri.Query().Get("grant")
	request := func(method, path, token, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		b.ServeHTTP(w, r)
		return w
	}
	if request("GET", "/v1/challenge", "wrong", "").Code != 401 {
		t.Fatal("invalid grant accepted")
	}
	w := request("GET", "/v1/challenge", grant, "")
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var c object
	_ = json.Unmarshal(w.Body.Bytes(), &c)
	session := c["session"].(string)
	if request("GET", "/v1/challenge", grant, "").Code != 401 {
		t.Fatal("grant replay accepted")
	}
	if request("POST", "/v1/result", session, `{"id":"old","token":"x"}`).Code != 400 {
		t.Fatal("wrong ID accepted")
	}
	if request("CONNECT", "example.com:443", session, "").Code != 403 {
		t.Fatal("open proxy")
	}
	if request("POST", "/v1/result", session, `{"id":"job1","token":"success"}`).Code != 200 {
		t.Fatal("result failed")
	}
	if request("POST", "/v1/result", session, `{"id":"job1","token":"success"}`).Code != 401 {
		t.Fatal("session survived completion")
	}
}
func TestReplacementAndExpiry(t *testing.T) {
	b := newTestBroker()
	first, _ := b.pair()
	u, _ := url.Parse(first["uri"].(string))
	_, _ = b.pair()
	r := httptest.NewRequest("GET", "/v1/challenge", nil)
	r.Header.Set("Authorization", "Bearer "+u.Query().Get("grant"))
	if _, ok := b.authorize(r, true); ok {
		t.Fatal("old pair grant valid")
	}
	b.current.Challenge.Expires = time.Now().Add(-time.Second).Unix()
	if _, ok := b.authorize(r, true); ok {
		t.Fatal("expired grant valid")
	}
	if b.current != nil {
		t.Fatal("expired job retained")
	}
}
func TestPersistentTLSIdentity(t *testing.T) {
	dir := t.TempDir()
	cert, pin, e := certificate(dir)
	if e != nil || len(cert.Certificate) != 1 || len(pin) != 64 {
		t.Fatalf("identity: %v", e)
	}
	_, again, e := certificate(dir)
	if e != nil || pin != again {
		t.Fatal("identity changed")
	}
}

func TestEscapedResultAtTokenLimit(t *testing.T) {
	b := newTestBroker()
	_, _ = b.pair()
	j := b.current
	j.Claimed = true
	// Escaped JSON exceeds32768 bytes although the token is exactly16384 bytes.
	token := strings.Repeat("\"\\", 8192)
	body, _ := json.Marshal(object{"id": j.Challenge.ID, "token": token})
	if len(body) <= 32768 {
		t.Fatal("fixture did not exercise escaped body boundary")
	}
	r := httptest.NewRequest("POST", "/v1/result", strings.NewReader(string(body)))
	r.Header.Set("Authorization", "Bearer "+j.Session)
	w := httptest.NewRecorder()
	b.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("valid boundary token rejected: %d", w.Code)
	}
}

func TestStaleHTTPActionCannotRevokeReplacement(t *testing.T) {
	for _, action := range []string{"cancel", "result"} {
		t.Run(action, func(t *testing.T) {
			b := newTestBroker()
			_, _ = b.pair()
			old := b.current
			old.Claimed = true
			body := ""
			if action == "result" {
				body = `{"id":"job1","token":"fixture-answer"}`
			}
			r := httptest.NewRequest("POST", "/v1/"+action, strings.NewReader(body))
			r.Header.Set("Authorization", "Bearer "+old.Session)
			core := b.core
			var replacement *job
			mutated := false
			b.core = func(req object) (object, error) {
				if req["command"] == "captcha_get" {
					// A new pairing wins after authentication, before the old HTTP action.
					b.core = core
					_, _ = b.pair()
					replacement = b.current
					b.core = func(req object) (object, error) {
						if req["command"] == "captcha_cancel" || req["command"] == "captcha_result" {
							mutated = true
						}
						return core(req)
					}
				}
				return core(req)
			}
			w := httptest.NewRecorder()
			b.ServeHTTP(w, r)
			if w.Code != 409 || b.current != replacement || replacement == nil || mutated {
				t.Fatal("old HTTP action mutated the replacement pairing")
			}
		})
	}
}

func TestResultRejectsTrailingJSONAndControlTokens(t *testing.T) {
	b := newTestBroker()
	_, _ = b.pair()
	j := b.current
	j.Claimed = true
	for _, body := range []string{
		`{"id":"job1","token":"answer"} {}`,
		`{"id":"job1","token":" "}`,
		`{"id":"job1","token":"answer\t"}`,
		`{"id":"job1","token":"answer\u0085"}`,
	} {
		r := httptest.NewRequest("POST", "/v1/result", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+j.Session)
		w := httptest.NewRecorder()
		b.ServeHTTP(w, r)
		if w.Code != 400 || b.current != j {
			t.Fatal("malformed answer accepted or pairing consumed")
		}
	}
}
