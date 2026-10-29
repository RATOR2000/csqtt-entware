package captcha

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"testing"
	"time"
)

// Contract of the published preview.10 Android Helper's Pairing/RouterSession.
// Exercise Service.Pair, rather than a broker fixture with its own port.
func TestPublishedHelperPairingTLSContract(t *testing.T) {
	s := testService(t, serviceCore(0))
	listen := s.listen
	var address string
	s.listen = func(network, requested string) (net.Listener, error) {
		ln, err := listen(network, requested)
		if err == nil {
			address = ln.Addr().String()
		}
		return ln, err
	}
	pair, err := s.Pair()
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(pair["helper_uri"].(string))
	if err != nil || u.Scheme != "csqtt-helper" || u.Host != "pair" || u.User != nil || u.Path != "" || u.Fragment != "" {
		t.Fatal("Helper would reject pairing URI")
	}
	q := u.Query()
	if len(q) != 5 || q.Get("host") != "192.168.99.1" || q.Get("port") != "9443" || s.Port() != "9443" {
		t.Fatal("pairing is incompatible with published Helper authority")
	}
	for _, key := range []string{"grant", "pin"} {
		if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(q.Get(key)) {
			t.Fatalf("invalid Helper %s format", key)
		}
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`).MatchString(q.Get("id")) {
		t.Fatal("invalid Helper challenge ID")
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			// Match Helper's explicit certificate pin instead of public CA/SAN trust.
			InsecureSkipVerify: true,
			VerifyConnection: func(cs tls.ConnectionState) error {
				cert := cs.PeerCertificates[0]
				pin := sha256.Sum256(cert.Raw)
				if hex.EncodeToString(pin[:]) != q.Get("pin") || time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
					return errors.New("Helper certificate pin or validity mismatch")
				}
				return nil
			},
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	claim, _ := http.NewRequest("GET", "https://"+net.JoinHostPort(q.Get("host"), q.Get("port"))+"/v1/challenge", nil)
	claim.Header.Set("Authorization", "Bearer "+q.Get("grant"))
	resp, err := client.Do(claim)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var body struct {
		ID       string `json:"id"`
		Redirect string `json:"redirect_uri"`
		Session  string `json:"session"`
		Expires  int64  `json:"expires_at"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || body.ID != q.Get("id") || !allowedURL(body.Redirect) || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(body.Session) || body.Expires <= time.Now().Unix() || body.Expires-time.Now().Unix() > 600 {
		t.Fatal("Helper would reject claimed challenge")
	}
}
