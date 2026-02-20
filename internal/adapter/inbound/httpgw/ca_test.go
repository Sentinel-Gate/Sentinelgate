package httpgw

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func testCAConfig(t *testing.T) CAConfig {
	t.Helper()
	dir := t.TempDir()
	return CAConfig{
		CertFile:      filepath.Join(dir, "ca-cert.pem"),
		KeyFile:       filepath.Join(dir, "ca-key.pem"),
		Organization:  "Test CA",
		ValidityYears: 1,
	}
}

// TestNewCAManager_GeneratesNew verifies that NewCAManager creates a new CA
// keypair when no files exist on disk, and that the generated cert is a valid CA.
func TestNewCAManager_GeneratesNew(t *testing.T) {
	cfg := testCAConfig(t)
	logger := testLogger()

	cm, err := NewCAManager(cfg, logger)
	if err != nil {
		t.Fatalf("NewCAManager: %v", err)
	}

	// Verify files were created
	if !fileExists(cfg.CertFile) {
		t.Fatalf("cert file not created: %s", cfg.CertFile)
	}
	if !fileExists(cfg.KeyFile) {
		t.Fatalf("key file not created: %s", cfg.KeyFile)
	}

	// Verify key file permissions (0600)
	info, err := os.Stat(cfg.KeyFile)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("key file perm = %o, want 0600", perm)
	}

	// Verify the cert is a CA
	if !cm.caCert.IsCA {
		t.Error("generated cert is not a CA")
	}
	if cm.caCert.Subject.Organization[0] != "Test CA" {
		t.Errorf("org = %q, want %q", cm.caCert.Subject.Organization[0], "Test CA")
	}

	// Verify key parses (implicitly tested by NewCAManager succeeding,
	// but let's also verify we can load it back)
	_, err = tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		t.Fatalf("LoadX509KeyPair from generated files: %v", err)
	}
}

// TestNewCAManager_LoadsExisting verifies that creating a second CAManager
// with the same file paths loads the existing CA rather than generating a new one.
func TestNewCAManager_LoadsExisting(t *testing.T) {
	cfg := testCAConfig(t)
	logger := testLogger()

	// First: generate
	cm1, err := NewCAManager(cfg, logger)
	if err != nil {
		t.Fatalf("first NewCAManager: %v", err)
	}

	// Second: load
	cm2, err := NewCAManager(cfg, logger)
	if err != nil {
		t.Fatalf("second NewCAManager: %v", err)
	}

	// Same serial number means same cert was loaded
	if cm1.caCert.SerialNumber.Cmp(cm2.caCert.SerialNumber) != 0 {
		t.Errorf("serial mismatch: %s vs %s",
			cm1.caCert.SerialNumber, cm2.caCert.SerialNumber)
	}
}

// TestNewCAManager_InconsistentFiles verifies that NewCAManager returns an error
// when only one of the cert/key files exists (inconsistent state).
func TestNewCAManager_InconsistentFiles(t *testing.T) {
	cfg := testCAConfig(t)
	logger := testLogger()

	// Create only the cert file
	if err := os.MkdirAll(filepath.Dir(cfg.CertFile), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(cfg.CertFile, []byte("fake"), 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	_, err := NewCAManager(cfg, logger)
	if err == nil {
		t.Fatal("expected error for inconsistent files, got nil")
	}
	t.Logf("got expected error: %v", err)
}

// TestGenerateCert_ValidLeaf verifies that GenerateCert produces a valid
// leaf certificate for the given domain, signed by the CA.
func TestGenerateCert_ValidLeaf(t *testing.T) {
	cfg := testCAConfig(t)
	logger := testLogger()

	cm, err := NewCAManager(cfg, logger)
	if err != nil {
		t.Fatalf("NewCAManager: %v", err)
	}

	cert, err := cm.GenerateCert("example.com")
	if err != nil {
		t.Fatalf("GenerateCert: %v", err)
	}

	leaf := cert.Leaf
	if leaf == nil {
		t.Fatal("leaf cert is nil")
	}

	// Verify CN
	if leaf.Subject.CommonName != "example.com" {
		t.Errorf("CN = %q, want %q", leaf.Subject.CommonName, "example.com")
	}

	// Verify DNSNames
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "example.com" {
		t.Errorf("DNSNames = %v, want [example.com]", leaf.DNSNames)
	}

	// Verify signed by CA
	if err := leaf.CheckSignatureFrom(cm.caCert); err != nil {
		t.Errorf("CheckSignatureFrom CA: %v", err)
	}

	// Verify cert chain includes CA cert
	if len(cert.Certificate) != 2 {
		t.Errorf("chain length = %d, want 2 (leaf + CA)", len(cert.Certificate))
	}
}

// TestGenerateCert_TLSUsable verifies the generated leaf cert can be used
// in an actual TLS handshake: create a TLS listener with the leaf cert and
// connect a client that trusts the CA.
func TestGenerateCert_TLSUsable(t *testing.T) {
	cfg := testCAConfig(t)
	logger := testLogger()

	cm, err := NewCAManager(cfg, logger)
	if err != nil {
		t.Fatalf("NewCAManager: %v", err)
	}

	domain := "localhost"
	leafCert, err := cm.GenerateCert(domain)
	if err != nil {
		t.Fatalf("GenerateCert: %v", err)
	}

	// Create TLS config for server
	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{*leafCert},
	}

	// Create TLS listener
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	// Server: accept one connection in background
	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		// Complete the handshake
		if tlsConn, ok := conn.(*tls.Conn); ok {
			serverErr <- tlsConn.Handshake()
		} else {
			serverErr <- fmt.Errorf("not a TLS connection")
		}
	}()

	// Client: trust the CA cert and connect
	caPool := x509.NewCertPool()
	caPool.AddCert(cm.caCert)

	clientTLS := &tls.Config{
		RootCAs:    caPool,
		ServerName: domain,
	}

	addr := ln.Addr().(*net.TCPAddr)
	conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", addr.Port), clientTLS)
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	conn.Close()

	// Check server handshake succeeded
	if sErr := <-serverErr; sErr != nil {
		t.Errorf("server handshake error: %v", sErr)
	}
}

// TestCACertPEM verifies that CACertPEM() returns valid PEM that can be
// parsed back to the same certificate.
func TestCACertPEM(t *testing.T) {
	cfg := testCAConfig(t)
	logger := testLogger()

	cm, err := NewCAManager(cfg, logger)
	if err != nil {
		t.Fatalf("NewCAManager: %v", err)
	}

	pemBytes := cm.CACertPEM()
	if len(pemBytes) == 0 {
		t.Fatal("CACertPEM returned empty bytes")
	}

	// Parse the PEM
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("failed to decode PEM block")
	}
	if block.Type != "CERTIFICATE" {
		t.Errorf("PEM type = %q, want CERTIFICATE", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	// Verify same serial
	if cert.SerialNumber.Cmp(cm.caCert.SerialNumber) != 0 {
		t.Errorf("serial mismatch: PEM=%s, manager=%s",
			cert.SerialNumber, cm.caCert.SerialNumber)
	}
}
