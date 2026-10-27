package manager

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestPrivateDirectoryCreatesAndRestrictsOwnedDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "runtime")
	if err := privateDir(path); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0755); err != nil {
			t.Fatal(err)
		}
		if err := privateDir(path); err != nil {
			t.Fatal(err)
		}
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
			t.Fatalf("owned private directory mode is not 0700: %v", err)
		}
	}
	file := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(file, []byte("sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := privateDir(file); err == nil {
		t.Fatal("accepted an existing regular file as a private directory")
	}
	data, _ := os.ReadFile(file)
	if string(data) != "sentinel" {
		t.Fatal("private directory preparation changed an unrelated file")
	}
}

func directoryLink(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("directory symlinks require Windows developer mode; Linux CI verifies this check")
		}
		t.Fatal(err)
	}
	return link, target
}

func TestRuntimeSymlinkIsRejectedBeforeChmodOrSettingsCreation(t *testing.T) {
	link, target := directoryLink(t)
	config := filepath.Join(t.TempDir(), "config", "settings.json")
	_, err := New(Options{Listen: "127.0.0.1:8080", RuntimeDir: link, ConfigPath: config})
	if err == nil {
		t.Fatal("accepted a symlink as the runtime directory")
	}
	if _, err = os.Stat(config); !os.IsNotExist(err) {
		t.Fatal("invalid runtime path still created settings")
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(target)
		if info.Mode().Perm() != 0755 {
			t.Fatal("runtime preparation chmod followed a directory symlink")
		}
	}
}

func TestConfigDirectorySymlinkIsRejectedBeforeReadingOrWritingSettings(t *testing.T) {
	link, target := directoryLink(t)
	path := filepath.Join(link, "settings.json")
	if _, err := loadSettings(path); err == nil {
		t.Fatal("loaded settings through a symlinked private directory")
	}
	if err := atomicJSON(path, Settings{}); err == nil {
		t.Fatal("wrote private settings through a symlinked directory")
	}
	if _, err := os.Stat(filepath.Join(target, "settings.json")); !os.IsNotExist(err) {
		t.Fatal("private configuration reached the symlink target")
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(target)
		if info.Mode().Perm() != 0755 {
			t.Fatal("config preparation chmod followed a directory symlink")
		}
	}
}
