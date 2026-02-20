package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTrustCACmd_Registered(t *testing.T) {
	found := false
	for _, cmd := range rootCmd.Commands() {
		if cmd.Name() == "trust-ca" {
			found = true
			break
		}
	}
	if !found {
		t.Error("trust-ca command not registered with rootCmd")
	}
}

func TestTrustCACmd_Flags(t *testing.T) {
	certFlag := trustCACmd.Flags().Lookup("cert")
	if certFlag == nil {
		t.Fatal("cert flag not registered")
	}
	if certFlag.DefValue != "" {
		t.Errorf("cert default = %q, want empty", certFlag.DefValue)
	}

	uninstallFlag := trustCACmd.Flags().Lookup("uninstall")
	if uninstallFlag == nil {
		t.Fatal("uninstall flag not registered")
	}
	if uninstallFlag.DefValue != "false" {
		t.Errorf("uninstall default = %q, want %q", uninstallFlag.DefValue, "false")
	}
}

func TestTrustCACmd_Description(t *testing.T) {
	if trustCACmd.Short == "" {
		t.Error("trust-ca command missing Short description")
	}
	if trustCACmd.Long == "" {
		t.Error("trust-ca command missing Long description")
	}
}

// createTestCACert generates a self-signed CA cert PEM in a temp file.
func createTestCACert(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	path := filepath.Join(t.TempDir(), "ca-cert.pem")
	if err := os.WriteFile(path, pemData, 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	return path
}

func TestParsePEMCertificate_Valid(t *testing.T) {
	certPath := createTestCACert(t)
	data, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := parsePEMCertificate(data)
	if err != nil {
		t.Fatalf("parsePEMCertificate: %v", err)
	}
	if cert.Subject.CommonName != "Test CA" {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, "Test CA")
	}
}

func TestParsePEMCertificate_InvalidPEM(t *testing.T) {
	_, err := parsePEMCertificate([]byte("not a pem"))
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
	if !strings.Contains(err.Error(), "valid PEM") {
		t.Errorf("error = %q, want mention of valid PEM", err.Error())
	}
}

func TestParsePEMCertificate_WrongBlockType(t *testing.T) {
	block := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{1, 2, 3}})
	_, err := parsePEMCertificate(block)
	if err == nil {
		t.Error("expected error for wrong PEM block type")
	}
	if !strings.Contains(err.Error(), "RSA PRIVATE KEY") {
		t.Errorf("error = %q, want mention of block type", err.Error())
	}
}

func TestSHA256Fingerprint(t *testing.T) {
	certPath := createTestCACert(t)
	data, _ := os.ReadFile(certPath)
	cert, _ := parsePEMCertificate(data)

	fp := sha256Fingerprint(cert.Raw)
	// Fingerprint should be 32 bytes = 64 hex chars with 31 colons.
	parts := strings.Split(fp, ":")
	if len(parts) != 32 {
		t.Errorf("fingerprint has %d parts, want 32", len(parts))
	}
	for _, part := range parts {
		if len(part) != 2 {
			t.Errorf("fingerprint part %q should be 2 chars", part)
		}
		// Should be uppercase hex.
		if part != strings.ToUpper(part) {
			t.Errorf("fingerprint part %q should be uppercase", part)
		}
	}
}

func TestResolveCACertPath_CustomPath(t *testing.T) {
	certPath := createTestCACert(t)
	resolved, err := resolveCACertPath(certPath)
	if err != nil {
		t.Fatalf("resolveCACertPath: %v", err)
	}
	if resolved != certPath {
		t.Errorf("resolved = %q, want %q", resolved, certPath)
	}
}

func TestResolveCACertPath_CustomPathNotFound(t *testing.T) {
	_, err := resolveCACertPath("/nonexistent/ca.pem")
	if err == nil {
		t.Error("expected error for nonexistent custom path")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %q, want mention of not found", err.Error())
	}
}

func TestTrustCommandForOS_Darwin(t *testing.T) {
	args, err := trustCommandForOS("darwin", "/tmp/ca.pem", false)
	if err != nil {
		t.Fatal(err)
	}
	if args[0] != "sudo" || args[1] != "security" || args[2] != "add-trusted-cert" {
		t.Errorf("darwin install = %v, want sudo security add-trusted-cert ...", args)
	}

	args, err = trustCommandForOS("darwin", "/tmp/ca.pem", true)
	if err != nil {
		t.Fatal(err)
	}
	if args[0] != "sudo" || args[1] != "security" || args[2] != "remove-trusted-cert" {
		t.Errorf("darwin uninstall = %v, want sudo security remove-trusted-cert ...", args)
	}
}

func TestTrustCommandForOS_Linux(t *testing.T) {
	args, err := trustCommandForOS("linux", "/tmp/ca.pem", false)
	if err != nil {
		t.Fatal(err)
	}
	if args[0] != "sudo" || args[1] != "cp" {
		t.Errorf("linux install = %v, want sudo cp ...", args)
	}
	if !strings.Contains(args[3], "sentinelgate-ca.crt") {
		t.Errorf("linux install dest = %q, want sentinelgate-ca.crt", args[3])
	}

	args, err = trustCommandForOS("linux", "/tmp/ca.pem", true)
	if err != nil {
		t.Fatal(err)
	}
	if args[0] != "sudo" || args[1] != "rm" {
		t.Errorf("linux uninstall = %v, want sudo rm ...", args)
	}
}

func TestTrustCommandForOS_Windows(t *testing.T) {
	args, err := trustCommandForOS("windows", "C:\\ca.pem", false)
	if err != nil {
		t.Fatal(err)
	}
	if args[0] != "certutil" || args[1] != "-addstore" {
		t.Errorf("windows install = %v, want certutil -addstore ...", args)
	}

	args, err = trustCommandForOS("windows", "C:\\ca.pem", true)
	if err != nil {
		t.Fatal(err)
	}
	if args[0] != "certutil" || args[1] != "-delstore" {
		t.Errorf("windows uninstall = %v, want certutil -delstore ...", args)
	}
}

func TestTrustCommandForOS_Unsupported(t *testing.T) {
	_, err := trustCommandForOS("freebsd", "/tmp/ca.pem", false)
	if err == nil {
		t.Error("expected error for unsupported OS")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("error = %q, want mention of unsupported", err.Error())
	}
}
