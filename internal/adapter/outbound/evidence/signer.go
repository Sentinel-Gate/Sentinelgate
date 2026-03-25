// Package evidence implements cryptographic signing and verification
// for tamper-proof audit evidence records.
package evidence

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
)

// ECDSASigner signs data using ECDSA P-256.
type ECDSASigner struct {
	key      *ecdsa.PrivateKey
	signerID string
}

// NewECDSASigner creates a signer by loading or generating an ECDSA P-256 key.
// If keyPath exists, the key is loaded. Otherwise, a new key is generated and saved.
func NewECDSASigner(keyPath string, signerID string) (*ECDSASigner, error) {
	var key *ecdsa.PrivateKey
	var err error

	if _, statErr := os.Stat(keyPath); statErr == nil {
		key, err = loadKey(keyPath)
		if err != nil {
			return nil, fmt.Errorf("load evidence key: %w", err)
		}
	} else {
		key, err = generateAndSaveKey(keyPath)
		if err != nil {
			return nil, fmt.Errorf("generate evidence key: %w", err)
		}
	}

	return &ECDSASigner{key: key, signerID: signerID}, nil
}

// Sign produces an ECDSA signature over the SHA-256 hash of data.
func (s *ECDSASigner) Sign(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, hash[:])
	if err != nil {
		return nil, fmt.Errorf("ecdsa sign: %w", err)
	}
	return sig, nil
}

// SignerID returns the signer instance identifier.
func (s *ECDSASigner) SignerID() string { return s.signerID }

// Algorithm returns the signing algorithm name.
func (s *ECDSASigner) Algorithm() string { return "ECDSA-P256" }

// PublicKeyPEM returns the PEM-encoded public key.
// L-21: Logs a warning if marshalling fails instead of silently returning nil.
func (s *ECDSASigner) PublicKeyPEM() []byte {
	der, err := x509.MarshalPKIXPublicKey(&s.key.PublicKey)
	if err != nil {
		slog.Warn("failed to marshal public key to PKIX", "signer_id", s.signerID, "error", err)
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// loadKey reads an ECDSA private key from a PEM file.
func loadKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		slog.Warn("trailing data after PEM block in key file", "path", path)
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse EC private key: %w", err)
	}
	// L-60: Validate the loaded key uses the expected P-256 curve.
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("evidence key must use P-256 curve, got %s", key.Curve.Params().Name)
	}
	return key, nil
}

// generateAndSaveKey creates a new ECDSA P-256 key pair and saves the private key.
func generateAndSaveKey(path string) (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}

	// Ensure directory exists.
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("create key directory: %w", err)
		}
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, fmt.Errorf("create key file: %w", err)
	}
	var writeOK bool
	defer func() {
		// M-48: Close explicitly before checking writeOK so flush errors are caught.
		if closeErr := f.Close(); closeErr != nil && writeOK {
			writeOK = false
		}
		if !writeOK {
			// L-30: Log os.Remove error instead of discarding.
			if removeErr := os.Remove(path); removeErr != nil {
				slog.Warn("failed to remove partial key file", "path", path, "error", removeErr)
			}
		}
	}()

	if err := pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}); err != nil {
		return nil, err
	}
	if err := f.Sync(); err != nil {
		return nil, fmt.Errorf("sync key file: %w", err)
	}
	writeOK = true

	return key, nil
}

// ECDSAVerifier verifies ECDSA P-256 signatures.
type ECDSAVerifier struct {
	pubKey *ecdsa.PublicKey
}

// NewECDSAVerifier creates a verifier from a PEM-encoded public key.
func NewECDSAVerifier(pubKeyPEM []byte) (*ECDSAVerifier, error) {
	block, rest := pem.Decode(pubKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		slog.Warn("trailing data after PEM block in public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not ECDSA")
	}
	return &ECDSAVerifier{pubKey: ecPub}, nil
}

// NewECDSAVerifierFromKeyFile loads the public key from a private key PEM file.
func NewECDSAVerifierFromKeyFile(keyPath string) (*ECDSAVerifier, error) {
	key, err := loadKey(keyPath)
	if err != nil {
		return nil, err
	}
	return &ECDSAVerifier{pubKey: &key.PublicKey}, nil
}

// Verify checks an ECDSA signature against the SHA-256 hash of data.
func (v *ECDSAVerifier) Verify(data []byte, signature []byte) (bool, error) {
	hash := sha256.Sum256(data)
	return ecdsa.VerifyASN1(v.pubKey, hash[:], signature), nil
}
