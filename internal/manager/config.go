// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
package manager

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"unicode"

	"github.com/RATOR2000/csqtt-entware/internal/wgbridge"
)

type Settings struct {
	Peer             string `json:"peer"`
	Password         string `json:"password"`
	VKLink           string `json:"vk_link"`
	Enabled          bool   `json:"enabled"`
	ServerPrivateKey string `json:"server_private_key"`
	ClientPrivateKey string `json:"client_private_key"`
	ProfileAddress   string `json:"profile_address,omitempty"`
	DNS              string `json:"dns"`
}

func atomicJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if err := privatePath(path); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".csqtt-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, path)
}

func privatePath(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("unsafe_private_file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return errors.New("private_file_permissions")
	}
	return nil
}

func loadSettings(path string) (Settings, error) {
	var s Settings
	if err := privatePath(path); err != nil {
		return s, err
	}
	f, err := os.Open(path)
	if err == nil {
		data, readErr := io.ReadAll(io.LimitReader(f, 16385))
		closeErr := f.Close()
		if readErr != nil || closeErr != nil || len(data) > 16384 {
			return s, errors.New("invalid_settings")
		}
		d := json.NewDecoder(strings.NewReader(string(data)))
		d.DisallowUnknownFields()
		if err = d.Decode(&s); err != nil {
			return s, errors.New("invalid_settings")
		}
		if d.Decode(&struct{}{}) != io.EOF {
			return s, errors.New("invalid_settings")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return s, err
	}
	if s.DNS == "" {
		s.DNS = "9.9.9.9"
	}
	if s.ServerPrivateKey == "" {
		k, e := wgbridge.GenerateKeys()
		if e != nil {
			return s, e
		}
		s.ServerPrivateKey = k.PrivateKey
	}
	if s.ClientPrivateKey == "" {
		k, e := wgbridge.GenerateKeys()
		if e != nil {
			return s, e
		}
		s.ClientPrivateKey = k.PrivateKey
	}
	if _, err = wgbridge.PublicKey(s.ServerPrivateKey); err != nil {
		return s, errors.New("invalid_server_key")
	}
	if _, err = wgbridge.PublicKey(s.ClientPrivateKey); err != nil {
		return s, errors.New("invalid_client_key")
	}
	return s, atomicJSON(path, s)
}

func validateCredentials(s Settings) error {
	host, port, err := net.SplitHostPort(s.Peer)
	if err != nil || host == "" || len(s.Peer) > 255 {
		return errors.New("Укажите сервер в формате host:port")
	}
	p, e := strconv.Atoi(port)
	if e != nil || p < 1 || p > 65535 {
		return errors.New("Некорректный порт сервера")
	}
	if strings.IndexFunc(host, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r) || strings.ContainsRune("/|\\", r)
	}) >= 0 {
		return errors.New("Некорректный адрес сервера")
	}
	if len(s.Password) < 4 || len(s.Password) > 128 || strings.Contains(s.Password, "|") || strings.IndexFunc(s.Password, unicode.IsControl) >= 0 {
		return errors.New("Пароль должен содержать от 4 до 128 байт без управляющих символов")
	}
	if len(s.VKLink) < 16 || len(s.VKLink) > 2048 || strings.IndexFunc(s.VKLink, unicode.IsControl) >= 0 {
		return errors.New("Укажите ссылку на звонок VK")
	}
	dns, e := netip.ParseAddr(s.DNS)
	if e != nil || !dns.Is4() || !dns.IsGlobalUnicast() || dns.IsPrivate() {
		return errors.New("Укажите публичный IPv4 DNS")
	}
	return nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return hex.EncodeToString(b), err
}

func checkIPv4Only() error {
	data, err := os.ReadFile("/proc/net/if_inet6")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		raw, e := hex.DecodeString(fields[0])
		if e != nil || len(raw) != 16 {
			continue
		}
		ip, ok := netip.AddrFromSlice(raw)
		if ok && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			return fmt.Errorf("IPv6 активен: первая версия требует IPv4 без обхода VPN")
		}
	}
	return nil
}
