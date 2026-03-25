package service

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	evidenceAdapter "github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/evidence"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
)

func TestEvidenceService_RecordEvidence(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test-key.pem")
	outputPath := filepath.Join(dir, "evidence.jsonl")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	signer, err := evidenceAdapter.NewECDSASigner(keyPath, "test-instance")
	if err != nil {
		t.Fatalf("NewECDSASigner: %v", err)
	}

	store, err := evidenceAdapter.NewFileStore(outputPath)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}

	svc := NewEvidenceService(signer, store, logger, nil)

	// Record 3 audit entries.
	for i := 0; i < 3; i++ {
		svc.RecordEvidence(audit.AuditRecord{
			Timestamp:    time.Now(),
			ToolName:     "read_file",
			Decision:     "allow",
			IdentityName: "test-user",
			Protocol:     "mcp",
			LatencyMicros: 100,
		})
	}

	if err := svc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if svc.LastError() != nil {
		t.Errorf("unexpected error: %v", svc.LastError())
	}

	stats := svc.Stats()
	if stats.RecordCount != 3 {
		t.Errorf("RecordCount = %d, want 3", stats.RecordCount)
	}
	if stats.LastHash == "" {
		t.Error("LastHash should not be empty after recording")
	}

	// Verify the output file.
	result, err := evidenceAdapter.VerifyFile(outputPath, keyPath)
	if err != nil {
		t.Fatalf("VerifyFile: %v", err)
	}

	if result.TotalRecords != 3 {
		t.Errorf("TotalRecords = %d, want 3", result.TotalRecords)
	}
	if result.ValidSignatures != 3 {
		t.Errorf("ValidSignatures = %d, want 3", result.ValidSignatures)
	}
	if result.InvalidSigs != 0 {
		t.Errorf("InvalidSigs = %d, want 0", result.InvalidSigs)
	}
	if !result.ChainValid {
		t.Errorf("ChainValid = false, want true (break at %d, error: %s)", result.ChainBreakAt, result.FirstError)
	}
}

func TestEvidenceService_PublicKeyPEM(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test-key.pem")
	outputPath := filepath.Join(dir, "evidence.jsonl")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	signer, _ := evidenceAdapter.NewECDSASigner(keyPath, "test")
	store, _ := evidenceAdapter.NewFileStore(outputPath)
	svc := NewEvidenceService(signer, store, logger, nil)
	defer svc.Close()

	pem := svc.PublicKeyPEM()
	if len(pem) == 0 {
		t.Error("PublicKeyPEM returned empty")
	}
}

func TestEvidenceRecorder_WrapsAuditRecorder(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "test-key.pem")
	outputPath := filepath.Join(dir, "evidence.jsonl")
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	signer, _ := evidenceAdapter.NewECDSASigner(keyPath, "test")
	store, _ := evidenceAdapter.NewFileStore(outputPath)
	evSvc := NewEvidenceService(signer, store, logger, nil)

	// Mock inner recorder.
	inner := &mockAuditRecorder{}
	recorder := NewEvidenceRecorder(inner, evSvc)

	recorder.Record(audit.AuditRecord{
		Timestamp:    time.Now(),
		ToolName:     "write_file",
		Decision:     "deny",
		IdentityName: "attacker",
	})

	evSvc.Close()

	if inner.count != 1 {
		t.Errorf("inner recorder count = %d, want 1", inner.count)
	}

	stats := evSvc.Stats()
	if stats.RecordCount != 1 {
		t.Errorf("evidence RecordCount = %d, want 1", stats.RecordCount)
	}
}

type mockAuditRecorder struct {
	count int
}

func (m *mockAuditRecorder) Record(record audit.AuditRecord) {
	m.count++
}
