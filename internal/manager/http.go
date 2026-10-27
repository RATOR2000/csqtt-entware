// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package manager

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

//go:embed web/*
var assets embed.FS

func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func (m *Manager) allowedHost(hostport string) bool {
	// The two loopback authorities are the documented SSH tunnel, not a
	// wildcard exception for arbitrary local origins or reverse proxies.
	return hostport == m.opts.Listen || hostport == "127.0.0.1:18080" || hostport == "localhost:18080"
}
func (m *Manager) protected(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if !m.allowedHost(r.Host) {
			respond(w, 403, map[string]string{"error": "host_not_allowed"})
			return
		}
		origin := r.Header.Get("Origin")
		if origin != "" {
			u, e := url.Parse(origin)
			if e != nil || u.Scheme != "http" || u.Host != r.Host || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.User != nil {
				respond(w, 403, map[string]string{"error": "origin_not_allowed"})
				return
			}
		}
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
			respond(w, 403, map[string]string{"error": "cross_site_request"})
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" || r.URL.Path == "/api/wireguard.conf" {
			token := r.Header.Get("X-CSRF-Token")
			if subtle.ConstantTimeCompare([]byte(token), []byte(m.token)) != 1 {
				respond(w, 403, map[string]string{"error": "csrf_required"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		respond(w, 415, map[string]string{"error": "json_required"})
		return false
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(&struct{}{}) != io.EOF {
		respond(w, 400, map[string]string{"error": "invalid_json"})
		return false
	}
	return true
}

func (m *Manager) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/session", func(w http.ResponseWriter, r *http.Request) { respond(w, 200, map[string]string{"csrf": m.token}) })
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) { respond(w, 200, m.Snapshot()) })
	mux.HandleFunc("GET /api/settings", func(w http.ResponseWriter, r *http.Request) {
		m.op.Lock()
		out := map[string]any{"peer": m.settings.Peer, "dns": m.settings.DNS, "password_saved": m.settings.Password != "", "vk_link_saved": m.settings.VKLink != ""}
		m.op.Unlock()
		respond(w, 200, out)
	})
	mux.HandleFunc("POST /api/settings", func(w http.ResponseWriter, r *http.Request) {
		var in SettingsInput
		if !decodeBody(w, r, &in) {
			return
		}
		if err := m.Save(in); err != nil {
			respond(w, 400, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/connect", func(w http.ResponseWriter, r *http.Request) {
		var in struct{}
		if !decodeBody(w, r, &in) {
			return
		}
		if err := m.Connect(); err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/disconnect", func(w http.ResponseWriter, r *http.Request) {
		var in struct{}
		if !decodeBody(w, r, &in) {
			return
		}
		if err := m.Disconnect(); err != nil {
			respond(w, 500, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /api/wireguard.conf", func(w http.ResponseWriter, r *http.Request) {
		profile, err := m.Profile()
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="CSQTT.conf"`)
		_, _ = io.WriteString(w, profile)
	})
	mux.HandleFunc("POST /api/captcha/pair", func(w http.ResponseWriter, r *http.Request) {
		var in struct{}
		if !decodeBody(w, r, &in) {
			return
		}
		out, err := m.PairCaptcha()
		if err != nil {
			respond(w, 409, map[string]string{"error": err.Error()})
			return
		}
		respond(w, 200, out)
	})
	mux.HandleFunc("POST /api/captcha/cancel", func(w http.ResponseWriter, r *http.Request) {
		var in struct{}
		if !decodeBody(w, r, &in) {
			return
		}
		m.CancelCaptcha()
		respond(w, 200, map[string]bool{"ok": true})
	})
	public, _ := fs.Sub(assets, "web")
	files := http.FileServer(http.FS(public))
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		switch r.URL.Path {
		case "/", "/app.js", "/style.css":
			files.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
	return m.protected(mux)
}
