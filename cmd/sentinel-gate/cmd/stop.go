package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the running SentinelGate server",
	Long: `Stop a running SentinelGate server by reading its PID file and sending SIGTERM.

Works for servers started manually ("sentinel-gate start") or auto-started
by "sentinel-gate run".

The PID file is located at ~/.sentinelgate/server.pid.

Examples:
  # Stop the running server
  sentinel-gate stop`,
	RunE: runStop,
}

func init() {
	rootCmd.AddCommand(stopCmd)
}

func runStop(cmd *cobra.Command, args []string) error {
	pidPath := pidFilePath()

	pid := readPIDFile(pidPath)
	if pid == 0 {
		return fmt.Errorf("no server PID file found at %s\nIs the server running?", pidPath)
	}

	// Check if the process is actually alive.
	proc, err := os.FindProcess(pid)
	if err != nil {
		os.Remove(pidPath)
		return fmt.Errorf("invalid PID %d: %w", pid, err)
	}

	// Check if the process is actually alive.
	if !processIsAlive(proc) {
		os.Remove(pidPath)
		return fmt.Errorf("server process %d is not running (stale PID file removed)", pid)
	}

	// Send graceful stop signal (SIGTERM on Unix, Kill on Windows).
	fmt.Fprintf(os.Stderr, "Stopping SentinelGate server (PID %d)...\n", pid)
	if err := sendGracefulStop(proc); err != nil {
		return fmt.Errorf("failed to stop server: %w", err)
	}

	// Wait for the process to exit (poll every 200ms, max 10s).
	for i := 0; i < 50; i++ {
		time.Sleep(200 * time.Millisecond)
		if !processIsAlive(proc) {
			os.Remove(pidPath)
			fmt.Fprintf(os.Stderr, "Server stopped.\n")
			return nil
		}
	}

	// Still alive after 10s — force kill.
	fmt.Fprintf(os.Stderr, "Server did not stop gracefully, sending SIGKILL...\n")
	_ = proc.Kill()
	os.Remove(pidPath)
	fmt.Fprintf(os.Stderr, "Server killed.\n")
	return nil
}
