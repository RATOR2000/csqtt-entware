//go:build linux

package manager

import (
	"errors"
	"os"
	"syscall"
)

func privateDirectoryOwned(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

func securePrivateDir(path string, info os.FileInfo) error {
	if !privateDirectoryOwned(info) {
		return errors.New("private_directory_owner")
	}
	// Re-open without following a substituted symlink, then check the opened
	// directory again. fchmod operates on that verified descriptor rather than
	// a path an attacker could replace between the ownership check and chmod.
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(fd), path)
	defer dir.Close()
	actual, err := dir.Stat()
	if err != nil {
		return err
	}
	if !actual.IsDir() || !privateDirectoryOwned(actual) {
		return errors.New("private_directory_owner")
	}
	return dir.Chmod(0700)
}
