//go:build windows

package cmd

import (
	"os"

	"golang.org/x/sys/windows"
)

// gracefulSignals returns the OS signals to capture for graceful shutdown.
// On Windows, only os.Interrupt (Ctrl+C / CTRL_C_EVENT) is reliably delivered.
// SIGTERM does not exist on Windows.
func gracefulSignals() []os.Signal {
	return []os.Signal{os.Interrupt}
}

// processIsAlive checks if a process is still running on Windows
// by opening a handle and checking the exit code.
func processIsAlive(proc *os.Process) bool {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(proc.Pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle)

	var exitCode uint32
	if err := windows.GetExitCodeProcess(handle, &exitCode); err != nil {
		return false
	}
	// STILL_ACTIVE (259) means the process has not exited yet.
	return exitCode == 259
}

// sendGracefulStop terminates the process on Windows.
// Windows does not support SIGTERM; Kill() calls TerminateProcess.
func sendGracefulStop(proc *os.Process) error {
	return proc.Kill()
}
