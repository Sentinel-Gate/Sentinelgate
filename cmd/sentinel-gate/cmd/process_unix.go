//go:build !windows

package cmd

import (
	"os"
	"syscall"
)

// gracefulSignals returns the OS signals to capture for graceful shutdown.
// On Unix: SIGINT (Ctrl+C) and SIGTERM (kill).
func gracefulSignals() []os.Signal {
	return []os.Signal{syscall.SIGINT, syscall.SIGTERM}
}

// processIsAlive checks if a process is still running using Signal(0).
func processIsAlive(proc *os.Process) bool {
	return proc.Signal(syscall.Signal(0)) == nil
}

// sendGracefulStop sends SIGTERM for graceful shutdown on Unix.
func sendGracefulStop(proc *os.Process) error {
	return proc.Signal(syscall.SIGTERM)
}
