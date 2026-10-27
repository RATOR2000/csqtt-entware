package captcha

import (
	"errors"
	"net"
	"testing"
	"time"
)

func testService(t *testing.T, core func(object) (object, error)) *Service {
	t.Helper()
	s := NewService("192.168.99.1", t.TempDir(), "unused-test-control-socket")
	s.core = core
	s.listen = func(network, requested string) (net.Listener, error) {
		if network != "tcp4" || requested != "192.168.99.1:8443" {
			t.Errorf("helper listener escaped exact LAN authority: %s %s", network, requested)
		}
		return net.Listen("tcp4", "127.0.0.1:0")
	}
	t.Cleanup(s.Stop)
	return s
}

func serviceCore(delay time.Duration) func(object) (object, error) {
	return func(request object) (object, error) {
		switch request["command"] {
		case "captcha_get":
			return object{"ok": true, "captcha": object{"id": "test-challenge", "state": "manual", "expires_at": time.Now().Add(time.Minute).Unix(), "redirect_uri": "https://id.vk.com/captcha/test"}}, nil
		case "captcha_manual":
			time.Sleep(delay)
			return object{"ok": true}, nil
		case "captcha_cancel":
			return object{"ok": true}, nil
		default:
			return nil, errors.New("unexpected_test_command")
		}
	}
}

func TestPairingSurvivesSlowInitialManualTakeover(t *testing.T) {
	s := testService(t, serviceCore(1100*time.Millisecond))
	if _, err := s.Pair(); err != nil {
		t.Fatal(err)
	}
	// The former watcher checked the nil job after one second, then closed this
	// successful pairing as soon as Pair released the service mutex.
	time.Sleep(100 * time.Millisecond)
	s.mu.Lock()
	alive := s.server != nil && s.broker != nil
	if alive {
		s.broker.mu.Lock()
		alive = s.broker.current != nil
		s.broker.mu.Unlock()
	}
	s.mu.Unlock()
	if !alive {
		t.Fatal("expiry watcher closed a successful slow pairing")
	}
}

func TestStaleWatcherCannotCloseNewServiceOrRenewedJob(t *testing.T) {
	s := testService(t, serviceCore(0))
	if _, err := s.Pair(); err != nil {
		t.Fatal(err)
	}
	old := s.server
	s.Stop()
	if _, err := s.Pair(); err != nil {
		t.Fatal(err)
	}
	current := s.server
	if old == current {
		t.Fatal("test did not create a replacement service")
	}
	s.stopExpected(old, false)
	if s.server != current {
		t.Fatal("old timeout closed the replacement listener")
	}
	if s.stopExpected(current, true) || s.server != current {
		t.Fatal("expiry check closed a live challenge")
	}
	s.broker.mu.Lock()
	s.broker.current.Challenge.Expires = time.Now().Add(-time.Second).Unix()
	s.broker.mu.Unlock()
	if !s.stopExpected(current, true) || s.server != nil {
		t.Fatal("expired challenge did not close its listener")
	}
}

func TestPairFailureReleasesItsListener(t *testing.T) {
	s := testService(t, func(object) (object, error) { return nil, errors.New("core_unavailable") })
	if _, err := s.Pair(); err == nil {
		t.Fatal("pair succeeded without a core challenge")
	}
	if s.server != nil || s.broker != nil || s.cancel != nil {
		t.Fatal("failed pairing retained its listener or watcher")
	}
}
