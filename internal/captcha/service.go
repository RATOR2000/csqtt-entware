// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package captcha

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"
)

// The published Android Helper rejects pairing links for any other port.
const helperPort = "9443"

// Service hosts the existing certificate-pinned Android Helper protocol only
// while a human challenge is active. It shares the manager's Go runtime.
type Service struct {
	mu                sync.Mutex
	host, dir, socket string
	server            *http.Server
	broker            *broker
	cancel            context.CancelFunc
	core              func(object) (object, error)
	listen            func(string, string) (net.Listener, error)
}

func NewService(host, certDir, controlSocket string) *Service {
	return &Service{host: host, dir: certDir, socket: controlSocket,
		core: func(v object) (object, error) { return rpc(controlSocket, v) }, listen: net.Listen}
}

func (s *Service) Pair() (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var watchContext context.Context
	var watchServer *http.Server
	if s.server == nil {
		cert, pin, err := certificate(s.dir)
		if err != nil {
			return nil, errors.New("helper_certificate_unavailable")
		}
		host := net.ParseIP(s.host)
		if host == nil || !host.IsPrivate() || host.To4() == nil {
			return nil, errors.New("helper_requires_lan_address")
		}
		listener, err := s.listen("tcp4", net.JoinHostPort(s.host, helperPort))
		if err != nil {
			return nil, errors.New("helper_port_unavailable")
		}
		b := &broker{host: s.host, port: helperPort, pin: pin, core: s.core}
		server := &http.Server{Handler: b, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 8192, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}}
		ctx, cancel := context.WithCancel(context.Background())
		s.broker = b
		s.server = server
		s.cancel = cancel
		go func() { _ = server.Serve(tls.NewListener(listener, server.TLSConfig)) }()
		watchContext, watchServer = ctx, server
	}
	out, err := s.broker.pair()
	if err != nil {
		s.stopLocked()
		return nil, errors.New("no_active_captcha")
	}
	// A takeover can require slow control RPCs. Do not start expiry checks while
	// the first successful pairing has not yet created its job.
	if watchServer != nil {
		go s.watch(watchContext, watchServer)
	}
	return out, nil
}

func (s *Service) watch(ctx context.Context, expected *http.Server) {
	timer := time.NewTimer(5 * time.Minute)
	defer timer.Stop()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			s.stopExpected(expected, false)
			return
		case <-ticker.C:
			if s.stopExpected(expected, true) {
				return
			}
		}
	}
}

// Old watcher goroutines must never close a replacement listener. The expiry
// condition is checked while holding the same lock as Pair, not before waiting
// for it: a newly created or renewed job must not inherit a stale decision.
func (s *Service) stopExpected(expected *http.Server, expiredOnly bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.server != expected {
		return true
	}
	if expiredOnly {
		s.broker.mu.Lock()
		expired := s.broker.current == nil || s.broker.current.Challenge.Expires <= time.Now().Unix()
		s.broker.mu.Unlock()
		if !expired {
			return false
		}
	}
	s.stopLocked()
	return true
}

func (s *Service) stopLocked() {
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	if s.broker != nil {
		_, _ = s.broker.cancel()
		s.broker = nil
	}
	if s.server != nil {
		_ = s.server.Close()
		s.server = nil
	}
}

func (s *Service) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopLocked()
}

func (s *Service) Port() string { return helperPort }
