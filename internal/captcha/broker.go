// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package captcha

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
)

type object = map[string]any
type challenge struct {
	ID       string `json:"id"`
	State    string `json:"state"`
	Redirect string `json:"redirect_uri"`
	Expires  int64  `json:"expires_at"`
}
type job struct {
	Challenge      challenge
	Grant, Session string
	Claimed        bool
	Connections    map[net.Conn]bool
}
type broker struct {
	mu        sync.Mutex
	current   *job
	core      func(object) (object, error)
	host, pin string
	port      string
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func equal(a, b string) bool {
	return len(a) > 0 && len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
func response(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func rpc(socket string, req object) (object, error) {
	conn, err := net.DialTimeout("unix", socket, 3*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err = json.NewEncoder(conn).Encode(req); err != nil {
		return nil, err
	}
	var r object
	err = json.NewDecoder(io.LimitReader(conn, 65536)).Decode(&r)
	return r, err
}
func readChallenge(r object) (challenge, error) {
	var c challenge
	b, _ := json.Marshal(r["captcha"])
	if json.Unmarshal(b, &c) != nil || c.ID == "" || c.Expires <= time.Now().Unix() || !allowedURL(c.Redirect) {
		return c, errors.New("no_current_challenge")
	}
	return c, nil
}
func allowedHost(host string) bool {
	host = strings.ToLower(host)
	if strings.HasSuffix(host, ".") || net.ParseIP(host) != nil {
		return false
	}
	for _, base := range []string{"vk.com", "vk.ru", "ok.ru", "okcdn.ru"} {
		if host == base || strings.HasSuffix(host, "."+base) {
			return true
		}
	}
	return false
}
func allowedURL(raw string) bool {
	u, e := url.Parse(raw)
	return e == nil && u.Scheme == "https" && u.User == nil && (u.Port() == "" || u.Port() == "443") && allowedHost(u.Hostname())
}
func (b *broker) revokeLocked() {
	if b.current != nil {
		for c := range b.current.Connections {
			_ = c.Close()
		}
	}
	b.current = nil
}
func (b *broker) pair() (object, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, e := b.core(object{"command": "captcha_get"})
	if e != nil {
		return nil, e
	}
	c, e := readChallenge(r)
	if e != nil {
		return nil, e
	}
	r, e = b.core(object{"command": "captcha_manual", "id": c.ID})
	if e != nil || r["ok"] != true {
		return nil, errors.New("manual_takeover_failed")
	}
	b.revokeLocked()
	b.current = &job{Challenge: c, Grant: randomToken(), Session: randomToken(), Connections: map[net.Conn]bool{}}
	q := url.Values{"host": {b.host}, "port": {b.port}, "grant": {b.current.Grant}, "pin": {b.pin}, "id": {c.ID}}
	uri := "csqtt-helper://pair?" + q.Encode()
	return object{"ok": true, "uri": uri, "helper_uri": uri, "expires_at": c.Expires}, nil
}
func (b *broker) cancel() (object, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	j := b.current
	b.revokeLocked()
	if j == nil {
		return object{"ok": true}, nil
	}
	return b.core(object{"command": "captcha_cancel", "id": j.Challenge.ID})
}
func (b *broker) cancelExpected(j *job) (object, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.current != j {
		return nil, errors.New("stale_challenge")
	}
	b.revokeLocked()
	return b.core(object{"command": "captcha_cancel", "id": j.Challenge.ID})
}
func (b *broker) submitResult(j *job, token string) (object, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.current != j || j.Challenge.Expires <= time.Now().Unix() {
		return nil, errors.New("stale_challenge")
	}
	out, err := b.core(object{"command": "captcha_result", "id": j.Challenge.ID, "token": token})
	if err == nil && out["ok"] == true {
		b.revokeLocked()
	}
	return out, err
}
func (b *broker) authorize(r *http.Request, claim bool) (*job, bool) {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	b.mu.Lock()
	defer b.mu.Unlock()
	j := b.current
	if j == nil || j.Challenge.Expires <= time.Now().Unix() {
		b.revokeLocked()
		return nil, false
	}
	if claim {
		if j.Claimed || !equal(j.Grant, token) {
			return nil, false
		}
		j.Claimed = true
		return j, true
	}
	return j, j.Claimed && equal(j.Session, token)
}
func (b *broker) stillCurrent(j *job) bool {
	r, e := b.core(object{"command": "captcha_get"})
	if e != nil {
		return false
	}
	c, e := readChallenge(r)
	return e == nil && c.ID == j.Challenge.ID
}
func (b *broker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	claim := r.Method == "GET" && r.URL.Path == "/v1/challenge"
	j, ok := b.authorize(r, claim)
	if !ok {
		response(w, 401, object{"error": "expired_or_invalid_session"})
		return
	}
	if !b.stillCurrent(j) {
		b.mu.Lock()
		if b.current == j {
			b.revokeLocked()
		}
		b.mu.Unlock()
		response(w, 409, object{"error": "stale_challenge"})
		return
	}
	if claim {
		response(w, 200, object{"id": j.Challenge.ID, "redirect_uri": j.Challenge.Redirect, "expires_at": j.Challenge.Expires, "session": j.Session})
		return
	}
	if r.Method == http.MethodConnect {
		b.connect(w, r, j)
		return
	}
	if r.Method == "POST" && r.URL.Path == "/v1/result" {
		var v struct {
			ID    string `json:"id"`
			Token string `json:"token"`
		}
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536))
		dec.DisallowUnknownFields()
		if dec.Decode(&v) != nil || dec.Decode(&struct{}{}) != io.EOF || v.ID != j.Challenge.ID || len(v.Token) > 16384 || strings.TrimSpace(v.Token) == "" || strings.IndexFunc(v.Token, unicode.IsControl) >= 0 {
			response(w, 400, object{"error": "invalid_result"})
			return
		}
		out, e := b.submitResult(j, v.Token)
		if e != nil || out["ok"] != true {
			response(w, 409, object{"error": "result_rejected"})
			return
		}
		response(w, 200, object{"ok": true})
		return
	}
	if r.Method == "POST" && r.URL.Path == "/v1/cancel" {
		out, err := b.cancelExpected(j)
		if err != nil || out["ok"] != true {
			response(w, 409, object{"error": "cancel_rejected"})
			return
		}
		response(w, 200, object{"ok": true})
		return
	}
	response(w, 404, object{"error": "not_found"})
}
func publicIP(ip net.IP) bool {
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, cidr := range []string{"100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"} {
		_, n, _ := net.ParseCIDR(cidr)
		if n.Contains(ip) {
			return false
		}
	}
	return true
}
func (b *broker) connect(w http.ResponseWriter, r *http.Request, j *job) {
	host, port, e := net.SplitHostPort(r.Host)
	if e != nil || port != "443" || !allowedHost(host) {
		response(w, 403, object{"error": "destination_not_allowed"})
		return
	}
	b.mu.Lock()
	full := b.current != j || len(j.Connections) >= 16
	b.mu.Unlock()
	if full {
		response(w, 429, object{"error": "connection_limit"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	ips, e := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if e != nil || len(ips) == 0 {
		response(w, 502, object{"error": "dns_failed"})
		return
	}
	for _, ip := range ips {
		if !publicIP(ip) {
			response(w, 403, object{"error": "non_public_address"})
			return
		}
	}
	upstream, e := (&net.Dialer{}).DialContext(ctx, "tcp4", net.JoinHostPort(ips[0].String(), port))
	if e != nil {
		response(w, 502, object{"error": "connect_failed"})
		return
	}
	h, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		response(w, 500, object{"error": "http1_required"})
		return
	}
	downstream, rw, e := h.Hijack()
	if e != nil {
		upstream.Close()
		return
	}
	b.mu.Lock()
	if b.current != j || len(j.Connections) >= 16 {
		b.mu.Unlock()
		downstream.Close()
		upstream.Close()
		return
	}
	j.Connections[downstream] = true
	b.mu.Unlock()
	defer func() {
		downstream.Close()
		upstream.Close()
		b.mu.Lock()
		delete(j.Connections, downstream)
		b.mu.Unlock()
	}()
	deadline := time.Unix(j.Challenge.Expires, 0)
	_ = downstream.SetDeadline(deadline)
	_ = upstream.SetDeadline(deadline)
	_, _ = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	if rw.Flush() != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, rw); done <- struct{}{} }()
	go func() { _, _ = io.Copy(downstream, upstream); done <- struct{}{} }()
	<-done
}
func certificate(dir string) (tls.Certificate, string, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return tls.Certificate{}, "", err
	}
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	if os.IsNotExist(certErr) && os.IsNotExist(keyErr) {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return tls.Certificate{}, "", e
		}
		serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "CSQTT local CAPTCHA helper"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(10, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
		der, e := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if e != nil {
			return tls.Certificate{}, "", e
		}
		pk, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			return tls.Certificate{}, "", e
		}
		if e = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pk}), 0600); e != nil {
			return tls.Certificate{}, "", e
		}
		if e = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); e != nil {
			return tls.Certificate{}, "", e
		}
	}
	cert, e := tls.LoadX509KeyPair(certPath, keyPath)
	if e != nil {
		return cert, "", e
	}
	pin := sha256.Sum256(cert.Certificate[0])
	return cert, hex.EncodeToString(pin[:]), nil
}
