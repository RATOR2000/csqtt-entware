package manager

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestKeysAndProfileAddressPersistAcrossManagerRestart(t *testing.T) {
	m := newTestManager(t)
	first := m.settings
	loaded, err := loadSettings(m.opts.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if first.ServerPrivateKey != loaded.ServerPrivateKey || first.ClientPrivateKey != loaded.ClientPrivateKey {
		t.Fatal("restart rotated persistent bridge keys")
	}
	loaded.ProfileAddress = "11.8.0.2"
	if err = atomicJSON(m.opts.ConfigPath, loaded); err != nil {
		t.Fatal(err)
	}
	again, err := loadSettings(m.opts.ConfigPath)
	if err != nil || again.ProfileAddress != loaded.ProfileAddress || again.ServerPrivateKey != first.ServerPrivateKey {
		t.Fatal("profile address or keys were not persisted")
	}
}

func TestSettingsRejectUnknownTrailingAndOversizedJSON(t *testing.T) {
	for _, test := range []struct{ name, content string }{
		{"unknown", `{"unexpected":"value"}`},
		{"trailing object", `{} {}`},
		{"oversized padding", `{}` + strings.Repeat(" ", 20000)},
		{"garbage beyond limit", `{}` + strings.Repeat(" ", 20000) + `{"extra":true}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "settings.json")
			if err := os.WriteFile(path, []byte(test.content), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadSettings(path); err == nil {
				t.Fatal("accepted an invalid or oversized private configuration")
			}
		})
	}
}

func TestPrivateFilePermissionsAndSymlinkRefusal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix mode and symlink enforcement is verified in Linux CI")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "private", "settings.json")
	if _, err := loadSettings(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private settings mode is not 0600: %v", err)
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = loadSettings(path); err == nil {
		t.Fatal("accepted group/world readable private settings")
	}
	target := filepath.Join(directory, "target.json")
	if err = os.WriteFile(target, []byte(`{"sentinel":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link.json")
	if err = os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err = atomicJSON(link, Settings{}); err == nil {
		t.Fatal("atomic private write followed a symlink")
	}
	raw, _ := os.ReadFile(target)
	var unchanged map[string]bool
	if json.Unmarshal(raw, &unchanged) != nil || !unchanged["sentinel"] {
		t.Fatal("symlink target changed")
	}
}
