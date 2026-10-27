//go:build linux

package manager

import (
	"os/exec"
	"syscall"
)

func setupProcess(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM} }
