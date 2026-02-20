package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// Build information. Populated at build time via -ldflags.
var (
	Version   = "1.0.0-beta.1"
	Commit    = "none"
	BuildDate = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Long:  `Print the version, commit, and build date of sentinel-gate.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("sentinel-gate %s\n", Version)
		fmt.Printf("  Commit:     %s\n", Commit)
		fmt.Printf("  Built:      %s\n", BuildDate)
		fmt.Printf("  Go version: %s\n", runtime.Version())
		fmt.Printf("  OS/Arch:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
