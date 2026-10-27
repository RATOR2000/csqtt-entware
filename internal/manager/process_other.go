//go:build !linux

package manager

import "os/exec"

func setupProcess(cmd *exec.Cmd) {}
