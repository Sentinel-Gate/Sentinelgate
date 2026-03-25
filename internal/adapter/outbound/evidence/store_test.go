package evidence

import (
	"bufio"
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

// buildRecord creates a signed evidence record with the correct chain hash.
// prevHash is the hex SHA-256 of the previous serialized record line, or "" for genesis.
func buildRecord(t *testing.T, signer *ECDSASigner, id string, prevHash string) ev.Record {
	t.Helper()

	record := ev.Record{
		Version:   "1.0",
		ID:        id,
		Timestamp: time.Now().UTC(),
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

	// Sign canonical payload (signature.value is empty at this point).
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal canonical payload for %s: %v", id, err)
	}
	sig, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign record %s: %v", id, err)
	}
	record.Signature.Value = base64.StdEncoding.EncodeToString(sig)

	return record
}

// hashRecordLine returns the hex SHA-256 hash of the JSON-serialized record.
func hashRecordLine(t *testing.T, record ev.Record) string {
	t.Helper()
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal record for hashing: %v", err)
	}
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h)
}

func TestEvidenceStore_AppendAndRead(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "evidence.jsonl")
	keyPath := filepath.Join(dir, "test-key.pem")

	signer, err := NewECDSASigner(keyPath, "test-signer")
	if err != nil {
		t.Fatalf("NewECDSASigner: %v", err)
	}

	store, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}

	// Build and append 3 records with a proper chain.
	prevHash := ""
	var records []ev.Record
	for i := 0; i < 3; i++ {
		rec := buildRecord(t, signer, fmt.Sprintf("evt_%03d", i+1), prevHash)
		if err := store.Append(rec); err != nil {
			t.Fatalf("Append record %d: %v", i, err)
		}
		prevHash = hashRecordLine(t, rec)
		records = append(records, rec)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Read back from file and verify contents.
	f, err := os.Open(storePath)
	if err != nil {
		t.Fatalf("open evidence file for reading: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	idx := 0
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var got ev.Record
		if err := json.Unmarshal(line, &got); err != nil {
			t.Fatalf("unmarshal line %d: %v", idx, err)
		}

		if got.ID != records[idx].ID {
			t.Errorf("record %d: ID = %q, want %q", idx, got.ID, records[idx].ID)
		}
		if got.ChainHash != records[idx].ChainHash {
			t.Errorf("record %d: ChainHash = %q, want %q", idx, got.ChainHash, records[idx].ChainHash)
		}
		if got.Signature.Value == "" {
			t.Errorf("record %d: Signature.Value is empty", idx)
		}
		idx++
	}

	if err := scanner.Err(); err != nil {
		t.Fatalf("scanner error: %v", err)
	}
	if idx != 3 {
		t.Errorf("read %d records, want 3", idx)
	}
}

func TestEvidenceStore_ChainHash(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "evidence.jsonl")
	keyPath := filepath.Join(dir, "test-key.pem")

	signer, err := NewECDSASigner(keyPath, "chain-test")
	if err != nil {
		t.Fatalf("NewECDSASigner: %v", err)
	}

	store, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}

	prevHash := ""
	for i := 0; i < 5; i++ {
		rec := buildRecord(t, signer, fmt.Sprintf("chain_%03d", i+1), prevHash)
		if err := store.Append(rec); err != nil {
			t.Fatalf("Append record %d: %v", i, err)
		}
		prevHash = hashRecordLine(t, rec)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Use the verifier to confirm chain integrity.
	result, err := VerifyFile(storePath, keyPath)
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
	if result.ChainBreakAt != -1 {
		t.Errorf("ChainBreakAt = %d, want -1", result.ChainBreakAt)
	}
}

func TestEvidenceStore_EmptyStore(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "empty.jsonl")
	keyPath := filepath.Join(dir, "test-key.pem")

	// Create the signer (generates the key file needed by VerifyFile).
	if _, err := NewECDSASigner(keyPath, "empty-test"); err != nil {
		t.Fatalf("NewECDSASigner: %v", err)
	}

	store, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	// Close without appending anything.
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Verify an empty evidence file.
	result, err := VerifyFile(storePath, keyPath)
	if err != nil {
		t.Fatalf("VerifyFile on empty store: %v", err)
	}

	if result.TotalRecords != 0 {
		t.Errorf("TotalRecords = %d, want 0", result.TotalRecords)
	}
	if result.ValidSignatures != 0 {
		t.Errorf("ValidSignatures = %d, want 0", result.ValidSignatures)
	}
	if result.InvalidSigs != 0 {
		t.Errorf("InvalidSigs = %d, want 0", result.InvalidSigs)
	}
	if !result.ChainValid {
		t.Error("ChainValid = false, want true for empty store")
	}
}

func TestFileStore_Path(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "path-test.jsonl")

	store, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	defer store.Close()

	if got := store.Path(); got != storePath {
		t.Errorf("Path() = %q, want %q", got, storePath)
	}
}

func TestFileStore_CreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	nestedPath := filepath.Join(dir, "sub", "dir", "evidence.jsonl")

	store, err := NewFileStore(nestedPath)
	if err != nil {
		t.Fatalf("NewFileStore with nested path: %v", err)
	}
	defer store.Close()

	// The directory should have been created.
	info, err := os.Stat(filepath.Dir(nestedPath))
	if err != nil {
		t.Fatalf("stat nested dir: %v", err)
	}
	if !info.IsDir() {
		t.Error("nested path parent is not a directory")
	}
}
