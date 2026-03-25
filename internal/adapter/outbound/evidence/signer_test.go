package evidence

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewECDSASigner_GeneratesKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test-key.pem")

	signer, err := NewECDSASigner(keyPath, "test-instance")
	if err != nil {
		t.Fatalf("NewECDSASigner: %v", err)
	}

	// Key file should exist.
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("key file not created: %v", err)
	}

	if signer.Algorithm() != "ECDSA-P256" {
		t.Errorf("algorithm = %q, want ECDSA-P256", signer.Algorithm())
	}
	if signer.SignerID() != "test-instance" {
		t.Errorf("signerID = %q, want test-instance", signer.SignerID())
	}

	pubPEM := signer.PublicKeyPEM()
	if len(pubPEM) == 0 {
		t.Error("PublicKeyPEM returned empty")
	}
}

func TestNewECDSASigner_LoadsExistingKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test-key.pem")

	// Generate key first.
	signer1, err := NewECDSASigner(keyPath, "inst-1")
	if err != nil {
		t.Fatalf("first NewECDSASigner: %v", err)
	}
	pub1 := signer1.PublicKeyPEM()

	// Load the same key.
	signer2, err := NewECDSASigner(keyPath, "inst-2")
	if err != nil {
		t.Fatalf("second NewECDSASigner: %v", err)
	}
	pub2 := signer2.PublicKeyPEM()

	// Public keys should match (same key loaded).
	if string(pub1) != string(pub2) {
		t.Error("loaded key has different public key than generated key")
	}
}

func TestSignAndVerify(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test-key.pem")

	signer, err := NewECDSASigner(keyPath, "test")
	if err != nil {
		t.Fatalf("NewECDSASigner: %v", err)
	}

	data := []byte(`{"tool":"read_file","decision":"allow"}`)

	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("Sign returned empty signature")
	}

	// Verify with public key.
	verifier, err := NewECDSAVerifier(signer.PublicKeyPEM())
	if err != nil {
		t.Fatalf("NewECDSAVerifier: %v", err)
	}

	valid, err := verifier.Verify(data, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !valid {
		t.Error("valid signature rejected")
	}

	// Tamper with data.
	tampered := []byte(`{"tool":"delete_file","decision":"allow"}`)
	valid, _ = verifier.Verify(tampered, sig)
	if valid {
		t.Error("tampered data accepted")
	}
}

func TestVerifyFromKeyFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test-key.pem")

	signer, err := NewECDSASigner(keyPath, "test")
	if err != nil {
		t.Fatalf("NewECDSASigner: %v", err)
	}

	data := []byte("hello world")
	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	verifier, err := NewECDSAVerifierFromKeyFile(keyPath)
	if err != nil {
		t.Fatalf("NewECDSAVerifierFromKeyFile: %v", err)
	}

	valid, _ := verifier.Verify(data, sig)
	if !valid {
		t.Error("valid signature rejected when verifying from key file")
	}
}
