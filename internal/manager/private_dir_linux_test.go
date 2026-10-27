//go:build linux

package manager

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

type fileInfoWithOwner struct {
	os.FileInfo
	stat *syscall.Stat_t
}

func (f fileInfoWithOwner) Sys() any { return f.stat }

func TestPrivateDirectoryOwnerIsCheckedBeforeChmod(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing")
	if err := os.Mkdir(path, 0755); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !privateDirectoryOwned(info) {
		t.Fatal("own directory was rejected")
	}
	// Inject only metadata into the pre-chmod check. This covers a different
	// owner without requiring root or changing any real ownership in CI.
	foreign := fileInfoWithOwner{FileInfo: info, stat: &syscall.Stat_t{Uid: uint32(os.Geteuid()) + 1}}
	if privateDirectoryOwned(foreign) {
		t.Fatal("foreign directory metadata was accepted")
	}
	if err = securePrivateDir(path, foreign); err == nil {
		t.Fatal("private preparation accepted a foreign owner")
	}
	unchanged, _ := os.Stat(path)
	if unchanged.Mode().Perm() != 0755 {
		t.Fatal("foreign ownership was checked after changing permissions")
	}
}
