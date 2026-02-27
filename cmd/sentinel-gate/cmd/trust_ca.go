package cmd

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

var trustCACertPath string
var trustCAUninstall bool

var trustCACmd = &cobra.Command{
	Use:   "trust-ca",
	Short: "Add the SentinelGate CA certificate to the system trust store",
	Long: `Add or remove the SentinelGate TLS inspection CA certificate from the
system trust store.

When TLS inspection is enabled, SentinelGate auto-generates a CA certificate
at ~/.sentinelgate/ca-cert.pem. This command installs that certificate into
the OS trust store so HTTPS clients trust intercepted connections.

Supported platforms:
  - macOS:   Adds to System Keychain via 'security' command (requires sudo)
  - Linux:   Copies to /usr/local/share/ca-certificates/ and runs
             update-ca-certificates (Debian/Ubuntu) or update-ca-trust (RHEL/Fedora)
  - Windows: Uses certutil -addstore root

Examples:
  sentinel-gate trust-ca
  sentinel-gate trust-ca --cert /path/to/custom-ca.pem
  sentinel-gate trust-ca --uninstall`,
	RunE: runTrustCA,
}

func init() {
	trustCACmd.Flags().StringVar(&trustCACertPath, "cert", "", "path to CA certificate PEM file (default: ~/.sentinelgate/ca-cert.pem)")
	trustCACmd.Flags().BoolVar(&trustCAUninstall, "uninstall", false, "remove the CA certificate from the system trust store")
	rootCmd.AddCommand(trustCACmd)
}

func runTrustCA(cmd *cobra.Command, args []string) error {
	certPath, err := resolveCACertPath(trustCACertPath)
	if err != nil {
		return err
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate: %w", err)
	}

	cert, err := parsePEMCertificate(certPEM)
	if err != nil {
		return err
	}

	fingerprint := sha256Fingerprint(cert.Raw)
	fmt.Fprintf(cmd.OutOrStdout(), "Certificate: %s\n", certPath)
	fmt.Fprintf(cmd.OutOrStdout(), "Subject:     %s\n", cert.Subject.CommonName)
	fmt.Fprintf(cmd.OutOrStdout(), "SHA-256:     %s\n", fingerprint)
	fmt.Fprintln(cmd.OutOrStdout())

	if trustCAUninstall {
		return uninstallCA(cmd, certPath)
	}
	return installCA(cmd, certPath)
}

// resolveCACertPath returns the CA cert path, using the default if not overridden.
func resolveCACertPath(override string) (string, error) {
	if override != "" {
		if _, err := os.Stat(override); err != nil {
			return "", fmt.Errorf("certificate not found: %s", override)
		}
		return override, nil
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}

	certPath := filepath.Join(homeDir, ".sentinelgate", "ca-cert.pem")
	if _, err := os.Stat(certPath); err != nil {
		return "", fmt.Errorf("CA certificate not found at %s\nRun 'sentinel-gate start' first to generate the CA, or use --cert to specify a path", certPath)
	}
	return certPath, nil
}

// parsePEMCertificate parses a PEM-encoded certificate.
func parsePEMCertificate(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM: file does not contain valid PEM data")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("PEM block type is %q, expected CERTIFICATE", block.Type)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return cert, nil
}

// sha256Fingerprint returns a colon-separated SHA-256 fingerprint.
func sha256Fingerprint(data []byte) string {
	sum := sha256.Sum256(data)
	hexStr := hex.EncodeToString(sum[:])
	parts := make([]string, 0, 32)
	for i := 0; i < len(hexStr); i += 2 {
		parts = append(parts, strings.ToUpper(hexStr[i:i+2]))
	}
	return strings.Join(parts, ":")
}

// trustCommandForOS returns the shell command args to install/uninstall a CA cert.
func trustCommandForOS(goos, certPath string, uninstall bool) ([]string, error) {
	switch goos {
	case "darwin":
		if uninstall {
			return []string{"sudo", "security", "remove-trusted-cert", "-d", certPath}, nil
		}
		return []string{"sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", certPath}, nil
	case "linux":
		if uninstall {
			return []string{"sudo", "rm", "-f", "/usr/local/share/ca-certificates/sentinelgate-ca.crt"}, nil
		}
		return []string{"sudo", "cp", certPath, "/usr/local/share/ca-certificates/sentinelgate-ca.crt"}, nil
	case "windows":
		if uninstall {
			return []string{"certutil", "-delstore", "root", "SentinelGate"}, nil
		}
		return []string{"certutil", "-addstore", "root", certPath}, nil
	default:
		return nil, fmt.Errorf("unsupported operating system: %s", goos)
	}
}

// linuxUpdateCmd returns the command to update CA trust on Linux.
func linuxUpdateCmd() []string {
	// Try Debian/Ubuntu first, fallback to RHEL/Fedora.
	if _, err := exec.LookPath("update-ca-certificates"); err == nil {
		return []string{"sudo", "update-ca-certificates"}
	}
	return []string{"sudo", "update-ca-trust"}
}

func installCA(cmd *cobra.Command, certPath string) error {
	args, err := trustCommandForOS(runtime.GOOS, certPath, false)
	if err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Installing CA certificate...\n")
	fmt.Fprintf(cmd.OutOrStdout(), "Running: %s\n", strings.Join(args, " "))

	//nolint:gosec // args are constructed internally, not from user input
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to install CA: %s\n%s", err, string(out))
	}

	// On Linux, also run update-ca-certificates/update-ca-trust.
	if runtime.GOOS == "linux" {
		updateArgs := linuxUpdateCmd()
		fmt.Fprintf(cmd.OutOrStdout(), "Running: %s\n", strings.Join(updateArgs, " "))
		out, err = exec.Command(updateArgs[0], updateArgs[1:]...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to update CA trust: %s\n%s", err, string(out))
		}
	}

	fmt.Fprintln(cmd.OutOrStdout(), "\nCA certificate installed successfully.")
	fmt.Fprintln(cmd.OutOrStdout(), "HTTPS clients will now trust TLS-inspected connections.")
	return nil
}

func uninstallCA(cmd *cobra.Command, certPath string) error {
	args, err := trustCommandForOS(runtime.GOOS, certPath, true)
	if err != nil {
		return err
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Removing CA certificate...\n")
	fmt.Fprintf(cmd.OutOrStdout(), "Running: %s\n", strings.Join(args, " "))

	//nolint:gosec // args are constructed internally, not from user input
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove CA: %s\n%s", err, string(out))
	}

	// On Linux, also run update-ca-certificates/update-ca-trust.
	if runtime.GOOS == "linux" {
		updateArgs := linuxUpdateCmd()
		fmt.Fprintf(cmd.OutOrStdout(), "Running: %s\n", strings.Join(updateArgs, " "))
		out, err = exec.Command(updateArgs[0], updateArgs[1:]...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to update CA trust: %s\n%s", err, string(out))
		}
	}

	fmt.Fprintln(cmd.OutOrStdout(), "\nCA certificate removed successfully.")
	return nil
}
