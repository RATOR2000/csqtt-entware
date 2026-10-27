//go:build !linux

package manager

import "os"

// Linux enforces directory ownership using the effective UID. Host platforms
// still receive the common Lstat/symlink/type checks before changing the mode.
func securePrivateDir(path string, _ os.FileInfo) error { return os.Chmod(path, 0700) }
