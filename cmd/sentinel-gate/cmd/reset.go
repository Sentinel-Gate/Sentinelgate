package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/Sentinel-Gate/Sentinelgate/internal/config"
)

var (
	resetIncludeAudit bool
	resetIncludeCerts bool
	resetForce        bool
)

var resetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset SentinelGate to a clean state",
	Long: `Reset SentinelGate by removing persistent state files.

By default, only state.json (and its backup) is removed. This clears all
upstreams, policies, identities, and API keys created via the admin UI.

On next start, SentinelGate will boot with a clean state — either from
your YAML config (if present) or completely empty in zero-config mode.

Optional flags:
  --include-audit   Also remove audit log files
  --include-certs   Also remove TLS inspection CA certificates
  --force           Skip confirmation prompt

Examples:
  # Reset state only (interactive confirmation)
  sentinel-gate reset

  # Reset everything without prompting
  sentinel-gate reset --include-audit --include-certs --force`,
	RunE: runReset,
}

func init() {
	resetCmd.Flags().BoolVar(&resetIncludeAudit, "include-audit", false, "Also remove audit log files")
	resetCmd.Flags().BoolVar(&resetIncludeCerts, "include-certs", false, "Also remove TLS inspection CA certificates (~/.sentinelgate/)")
	resetCmd.Flags().BoolVar(&resetForce, "force", false, "Skip confirmation prompt")
	rootCmd.AddCommand(resetCmd)
}

func runReset(cmd *cobra.Command, args []string) error {
	// Resolve state file path (same logic as start command).
	statePath := stateFilePath
	if statePath == "" {
		statePath = os.Getenv("SENTINEL_GATE_STATE_PATH")
	}
	if statePath == "" {
		statePath = "./state.json"
	}

	// Build list of targets to remove.
	type target struct {
		path string
		desc string
	}
	var targets []target

	// Always include state.json and its backup.
	targets = append(targets, target{statePath, "state file"})
	targets = append(targets, target{statePath + ".bak", "state backup"})

	// Optional: audit logs.
	if resetIncludeAudit {
		// Check config for audit file path.
		cfg, err := loadConfigForReset()
		if err == nil && cfg.Audit.Output != "" && cfg.Audit.Output != "stdout" {
			// Format is "file:///path/to/audit.log"
			if path := parseFileURI(cfg.Audit.Output); path != "" {
				targets = append(targets, target{path, "audit log"})
			}
		}
		// Also check audit_file.dir for structured audit files.
		if err == nil && cfg.AuditFile.Dir != "" {
			targets = append(targets, target{cfg.AuditFile.Dir, "audit directory"})
		}
	}

	// Optional: TLS certs.
	if resetIncludeCerts {
		if home, err := os.UserHomeDir(); err == nil {
			certDir := filepath.Join(home, ".sentinelgate")
			targets = append(targets, target{certDir, "TLS certificates"})
		}
	}

	// Check what actually exists.
	var existing []target
	for _, t := range targets {
		if _, err := os.Stat(t.path); err == nil {
			existing = append(existing, t)
		}
	}

	if len(existing) == 0 {
		fmt.Fprintln(os.Stderr, "Nothing to reset — no state files found.")
		return nil
	}

	// Show what will be removed.
	fmt.Fprintln(os.Stderr, "The following will be removed:")
	for _, t := range existing {
		fmt.Fprintf(os.Stderr, "  - %s (%s)\n", t.path, t.desc)
	}

	// Confirm unless --force.
	if !resetForce {
		fmt.Fprint(os.Stderr, "\nProceed? [y/N] ")
		var answer string
		fmt.Scanln(&answer) //nolint:errcheck // interactive prompt, error irrelevant
		if answer != "y" && answer != "Y" {
			fmt.Fprintln(os.Stderr, "Aborted.")
			return nil
		}
	}

	// Remove targets.
	var errors int
	for _, t := range existing {
		if err := os.RemoveAll(t.path); err != nil {
			fmt.Fprintf(os.Stderr, "  ERROR removing %s: %v\n", t.path, err)
			errors++
		} else {
			fmt.Fprintf(os.Stderr, "  Removed %s\n", t.path)
		}
	}

	if errors > 0 {
		return fmt.Errorf("%d file(s) could not be removed", errors)
	}

	fmt.Fprintln(os.Stderr, "\nReset complete. SentinelGate will start fresh on next launch.")
	return nil
}

// loadConfigForReset attempts to load config to discover audit file paths.
// Returns a zero config on error (non-fatal for reset).
func loadConfigForReset() (*config.OSSConfig, error) {
	cfg, err := config.LoadConfigRaw()
	if err != nil {
		return &config.OSSConfig{}, err
	}
	cfg.SetDefaults()
	return cfg, nil
}

// parseFileURI extracts the file path from a "file:///path" URI.
// On Windows, handles file:///C:/path → C:/path (strips extra leading slash).
func parseFileURI(uri string) string {
	const prefix = "file://"
	if len(uri) > len(prefix) && uri[:len(prefix)] == prefix {
		path := uri[len(prefix):]
		// On Windows, file:///C:/path produces /C:/path after prefix trim.
		// Remove the leading slash before a drive letter.
		if len(path) >= 3 && path[0] == '/' && path[2] == ':' {
			path = path[1:]
		}
		return path
	}
	return ""
}
