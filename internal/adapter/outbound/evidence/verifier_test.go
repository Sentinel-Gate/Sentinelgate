package evidence

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	ev "github.com/Sentinel-Gate/Sentinelgate/internal/domain/evidence"
)

// writeValidEvidenceFile creates a valid evidence file with proper signatures and hash chain.
func writeValidEvidenceFile(t *testing.T, dir string, n int) (evidencePath, keyPath string) {
	t.Helper()
	keyPath = filepath.Join(dir, "test-key.pem")
	evidencePath = filepath.Join(dir, "evidence.jsonl")

	signer, err := NewECDSASigner(keyPath, "test-signer")
	if err != nil {
		t.Fatalf("NewECDSASigner: %v", err)
	}

	f, err := os.Create(evidencePath)
	if err != nil {
		t.Fatalf("create evidence file: %v", err)
	}
	defer f.Close()

	prevHash := ""

	for i := 0; i < n; i++ {
		record := ev.Record{
			Version:   "1.0",
			ID:        fmt.Sprintf("evt_test_%03d", i+1),
			Timestamp: time.Now(),
			Identity:  ev.IdentityInfo{UserID: "test-user", Protocol: "mcp"},
			Action: ev.ActionInfo{
				Tool:     "read_file",
				Decision: "allow",
			},
			Signature: ev.SignatureInfo{
				Algorithm: signer.Algorithm(),
				Signer:    signer.SignerID(),
			},
		}

		if prevHash == "" {
			record.ChainHash = "sha256:genesis"
		} else {
			record.ChainHash = "sha256:" + prevHash
		}

		// Sign canonical payload (record with empty signature value).
		payload, _ := json.Marshal(record)
		sig, signErr := signer.Sign(payload)
		if signErr != nil {
			t.Fatalf("sign record %d: %v", i, signErr)
		}
		record.Signature.Value = base64.StdEncoding.EncodeToString(sig)

		// Serialize the full record (with signature) — this is what goes to file.
		fullBytes, _ := json.Marshal(record)

		// Write as a line (json.Encoder adds newline).
		if _, err := f.Write(fullBytes); err != nil {
			t.Fatalf("write record %d: %v", i, err)
		}
		if _, err := f.Write([]byte("\n")); err != nil {
			t.Fatalf("write newline %d: %v", i, err)
		}

		// Compute hash for next chain link.
		// The verifier reads lines with scanner (strips newline), so hash the JSON without newline.
		h := sha256.Sum256(fullBytes)
		prevHash = fmt.Sprintf("%x", h)
	}

	return evidencePath, keyPath
}

func TestVerifyFile_ValidChain(t *testing.T) {
	dir := t.TempDir()
	evidencePath, keyPath := writeValidEvidenceFile(t, dir, 5)

	result, err := VerifyFile(evidencePath, keyPath)
	if err != nil {
		t.Fatalf("VerifyFile: %v", err)
	}

	if result.TotalRecords != 5 {
		t.Errorf("TotalRecords = %d, want 5", result.TotalRecords)
	}
	if result.ValidSignatures != 5 {
		t.Errorf("ValidSignatures = %d, want 5", result.ValidSignatures)
	}
	if result.InvalidSigs != 0 {
		t.Errorf("InvalidSigs = %d, want 0", result.InvalidSigs)
	}
	if !result.ChainValid {
		t.Errorf("ChainValid = false, want true (break at %d, error: %s)", result.ChainBreakAt, result.FirstError)
	}
}

func TestVerifyFile_TamperedRecord(t *testing.T) {
	dir := t.TempDir()
	evidencePath, keyPath := writeValidEvidenceFile(t, dir, 3)

	// Tamper with the file: change a decision in the middle record.
	data, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	tampered := make([]byte, len(data))
	copy(tampered, data)
	// Replace "allow" with "deny!" in the content (crude but effective).
	for i := 0; i < len(tampered)-5; i++ {
		if string(tampered[i:i+5]) == "allow" {
			copy(tampered[i:i+5], "deny!")
			break // tamper only first occurrence
		}
	}
	if err := os.WriteFile(evidencePath, tampered, 0600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}

	result, err := VerifyFile(evidencePath, keyPath)
	if err != nil {
		t.Fatalf("VerifyFile: %v", err)
	}

	if result.InvalidSigs == 0 {
		t.Error("expected invalid signatures after tampering")
	}
}

func TestVerifyFile_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test-key.pem")
	evidencePath := filepath.Join(dir, "evidence.jsonl")

	if _, err := NewECDSASigner(keyPath, "test"); err != nil {
		t.Fatalf("NewECDSASigner: %v", err)
	}
	if err := os.WriteFile(evidencePath, nil, 0600); err != nil {
		t.Fatalf("write empty file: %v", err)
	}

	result, err := VerifyFile(evidencePath, keyPath)
	if err != nil {
		t.Fatalf("VerifyFile: %v", err)
	}
	if result.TotalRecords != 0 {
		t.Errorf("TotalRecords = %d, want 0", result.TotalRecords)
	}
	if !result.ChainValid {
		t.Error("empty file should have valid chain")
	}
}

func TestVerifyFile_SingleRecord(t *testing.T) {
	dir := t.TempDir()
	evidencePath, keyPath := writeValidEvidenceFile(t, dir, 1)

	result, err := VerifyFile(evidencePath, keyPath)
	if err != nil {
		t.Fatalf("VerifyFile: %v", err)
	}

	if result.TotalRecords != 1 {
		t.Errorf("TotalRecords = %d, want 1", result.TotalRecords)
	}
	if result.ValidSignatures != 1 {
		t.Errorf("ValidSignatures = %d, want 1", result.ValidSignatures)
	}
	if !result.ChainValid {
		t.Error("single record chain should be valid")
	}
}
