package storage

import (
	"context"
	"testing"
	"time"

	ev "github.com/Sentinel-Gate/Sentinelgate/internal/domain/evidence"
)

func newTestEvidenceStore(t *testing.T) *VersionedEvidenceStore {
	t.Helper()
	dir := t.TempDir()
	vs, err := NewFileVersionedStore(dir)
	if err != nil {
		t.Fatalf("NewFileVersionedStore: %v", err)
	}
	return NewVersionedEvidenceStore(vs)
}

func TestEvidenceAdapter_AppendAndGet(t *testing.T) {
	s := newTestEvidenceStore(t)
	ctx := context.Background()

	record := ev.Record{
		Version:   "1.0",
		ID:        "evt_20260305_000001",
		Timestamp: time.Date(2026, 3, 5, 12, 0, 0, 0, time.UTC),
		ChainHash: "sha256:genesis",
		Identity:  ev.IdentityInfo{UserID: "test-agent", Protocol: "mcp"},
		Action:    ev.ActionInfo{Tool: "read_file", Decision: "allow"},
		Result:    ev.ResultInfo{LatencyMicros: 150},
		Signature: ev.SignatureInfo{Algorithm: "ECDSA-P256", Signer: "test", Value: "base64sig"},
	}

	if err := s.Append(record); err != nil {
		t.Fatalf("Append: %v", err)
	}

	got, err := s.GetRecord(ctx, "evt_20260305_000001")
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}

	if got.ID != record.ID {
		t.Errorf("ID = %q, want %q", got.ID, record.ID)
	}
	if got.ChainHash != "sha256:genesis" {
		t.Errorf("ChainHash = %q", got.ChainHash)
	}
	if got.Action.Tool != "read_file" {
		t.Errorf("Tool = %q", got.Action.Tool)
	}
}

func TestEvidenceAdapter_ListRecords(t *testing.T) {
	s := newTestEvidenceStore(t)
	ctx := context.Background()

	// Append 3 records.
	for i := 1; i <= 3; i++ {
		record := ev.Record{
			Version:   "1.0",
			ID:        "evt_" + string(rune('0'+i)),
			Timestamp: time.Now().UTC(),
			Signature: ev.SignatureInfo{Algorithm: "ECDSA-P256", Signer: "test", Value: "sig"},
		}
		_ = s.Append(record)
	}

	ids, err := s.ListRecords(ctx)
	if err != nil {
		t.Fatalf("ListRecords: %v", err)
	}
	if len(ids) != 3 {
		t.Fatalf("list length = %d, want 3", len(ids))
	}
}

func TestEvidenceAdapter_ChainState(t *testing.T) {
	s := newTestEvidenceStore(t)
	ctx := context.Background()

	// Initially no state.
	hash, seq, err := s.LoadChainState(ctx)
	if err != nil {
		t.Fatalf("LoadChainState: %v", err)
	}
	if hash != "" || seq != 0 {
		t.Errorf("initial state: hash=%q seq=%d", hash, seq)
	}

	// Save state.
	if err := s.SaveChainState(ctx, "abc123", 42); err != nil {
		t.Fatalf("SaveChainState: %v", err)
	}

	// Load back.
	hash, seq, err = s.LoadChainState(ctx)
	if err != nil {
		t.Fatalf("LoadChainState: %v", err)
	}
	if hash != "abc123" {
		t.Errorf("hash = %q, want abc123", hash)
	}
	if seq != 42 {
		t.Errorf("seq = %d, want 42", seq)
	}
}

func TestEvidenceAdapter_ChainStateNotInList(t *testing.T) {
	s := newTestEvidenceStore(t)
	ctx := context.Background()

	// Save chain state and a record.
	_ = s.SaveChainState(ctx, "hash", 1)
	_ = s.Append(ev.Record{
		Version:   "1.0",
		ID:        "evt_001",
		Timestamp: time.Now().UTC(),
		Signature: ev.SignatureInfo{Algorithm: "ECDSA-P256", Signer: "test", Value: "sig"},
	})

	// _chain should not appear in record list.
	ids, _ := s.ListRecords(ctx)
	for _, id := range ids {
		if id == "_chain" {
			t.Error("_chain should not appear in record list")
		}
	}
}
