package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	ev "github.com/Sentinel-Gate/Sentinelgate/internal/domain/evidence"
)

// EvidenceStore is the interface for persisting signed evidence records.
type EvidenceStore interface {
	Append(record ev.Record) error
	Close() error
}

// ChainStatePersister is an optional interface for persisting evidence chain
// state (prevHash + seqNum) across restarts.
type ChainStatePersister interface {
	SaveChainState(ctx context.Context, prevHash string, seqNum uint64) error
	LoadChainState(ctx context.Context) (prevHash string, seqNum uint64, err error)
}

// EvidenceService signs audit records and maintains a hash chain.
type EvidenceService struct {
	mu             sync.Mutex
	signer         ev.Signer
	store          EvidenceStore
	chainPersister ChainStatePersister // nil = no persistence
	logger         *slog.Logger
	prevHash       string // hex hash of previous serialized record
	seqNum         uint64
	lastError      error
}

// NewEvidenceService creates a new evidence service.
// If chainPersister is non-nil, chain state is loaded at construction and
// saved after each record, so restarts continue the chain instead of forking.
func NewEvidenceService(signer ev.Signer, store EvidenceStore, logger *slog.Logger, chainPersister ChainStatePersister) *EvidenceService {
	s := &EvidenceService{
		signer:         signer,
		store:          store,
		logger:         logger,
		chainPersister: chainPersister,
		prevHash:       "", // empty = genesis
	}

	if chainPersister != nil {
		prevHash, seqNum, err := chainPersister.LoadChainState(context.Background())
		if err != nil {
			logger.Error("evidence: failed to load chain state, starting from genesis", "error", err)
		} else if seqNum > 0 {
			s.prevHash = prevHash
			s.seqNum = seqNum
			logger.Info("evidence: restored chain state", "seq_num", seqNum, "prev_hash_prefix", truncHash(prevHash))
		}
	}

	return s
}

// truncHash returns at most 16 chars of a hash for safe logging.
func truncHash(h string) string {
	if len(h) > 16 {
		return h[:16] + "..."
	}
	return h
}

// RecordEvidence signs an audit record and appends it to the evidence chain.
// This is safe to call from multiple goroutines.
func (s *EvidenceService) RecordEvidence(ar audit.AuditRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()

	record := ev.RecordFromAudit(ar)

	// L-37: Increment seqNum tentatively; roll back if signing or persistence fails.
	s.seqNum++

	// Generate unique ID.
	record.ID = fmt.Sprintf("evt_%s_%06d", ar.Timestamp.Format("20060102150405"), s.seqNum)

	// Set chain hash.
	if s.prevHash == "" {
		record.ChainHash = "sha256:genesis"
	} else {
		record.ChainHash = "sha256:" + s.prevHash
	}

	// Set signature metadata.
	record.Signature = ev.SignatureInfo{
		Algorithm: s.signer.Algorithm(),
		Signer:    s.signer.SignerID(),
	}

	// Compute canonical payload (record without signature value).
	payload, err := json.Marshal(record)
	if err != nil {
		s.logger.Error("evidence: marshal payload failed", "error", err)
		s.seqNum-- // L-37: roll back seqNum on failure
		s.lastError = err
		return
	}

	// Sign the payload.
	sig, err := s.signer.Sign(payload)
	if err != nil {
		s.logger.Error("evidence: signing failed", "error", err)
		s.seqNum-- // L-37: roll back seqNum on sign failure
		s.lastError = err
		return
	}
	record.Signature.Value = base64.StdEncoding.EncodeToString(sig)

	// Compute the chain hash from the full serialized record (with signature)
	// before persisting, so we can atomically commit both the record and chain state.
	fullBytes, err2 := json.Marshal(record)
	if err2 != nil {
		s.logger.Error("failed to marshal evidence record for chain hash", "error", err2)
		s.seqNum--
		s.lastError = err2
		return
	}
	h := sha256.Sum256(fullBytes)
	newHash := fmt.Sprintf("%x", h)

	// Persist chain state first so that if it fails, the record is not appended
	// and no fork can occur on restart.
	if s.chainPersister != nil {
		if err := s.chainPersister.SaveChainState(context.Background(), newHash, s.seqNum); err != nil {
			s.logger.Error("evidence: failed to save chain state, skipping record to avoid chain fork", "error", err)
			s.seqNum-- // rollback sequence number since the record was not persisted
			s.lastError = err
			return
		}
	}

	// Persist the evidence record.
	if err := s.store.Append(record); err != nil {
		s.logger.Error("evidence: store append failed", "error", err)
		s.seqNum--
		s.lastError = err
		// H-6: Rollback persisted chain state since Append failed after SaveChainState succeeded.
		if s.chainPersister != nil {
			rollbackHash := s.prevHash
			if rbErr := s.chainPersister.SaveChainState(context.Background(), rollbackHash, s.seqNum); rbErr != nil {
				s.logger.Error("evidence: CRITICAL chain state rollback failed", "error", rbErr)
			}
		}
		return
	}

	// Update in-memory chain state only after both persists succeeded.
	s.prevHash = newHash
}

// Close flushes and closes the evidence store.
func (s *EvidenceService) Close() error {
	return s.store.Close()
}

// LastError returns the last error encountered during evidence recording.
func (s *EvidenceService) LastError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastError
}

// PublicKeyPEM returns the signer's public key for verification.
func (s *EvidenceService) PublicKeyPEM() []byte {
	return s.signer.PublicKeyPEM()
}

// Stats returns evidence chain statistics.
func (s *EvidenceService) Stats() EvidenceStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return EvidenceStats{
		RecordCount: s.seqNum,
		LastHash:    s.prevHash,
	}
}

// EvidenceStats holds evidence chain statistics.
type EvidenceStats struct {
	RecordCount uint64 `json:"record_count"`
	LastHash    string `json:"last_hash"`
}

// EvidenceRecorder wraps AuditRecorder to also record evidence.
// It implements the audit.AuditRecorder pattern (non-blocking).
type EvidenceRecorder struct {
	inner    AuditRecorder
	evidence *EvidenceService
}

// AuditRecorder is the interface for recording audit entries.
type AuditRecorder interface {
	Record(record audit.AuditRecord)
}

// NewEvidenceRecorder wraps an existing audit recorder with evidence recording.
func NewEvidenceRecorder(inner AuditRecorder, evidence *EvidenceService) *EvidenceRecorder {
	return &EvidenceRecorder{inner: inner, evidence: evidence}
}

// Record sends the audit record to both the original recorder and the evidence service.
func (r *EvidenceRecorder) Record(record audit.AuditRecord) {
	// Always record to the original audit system first.
	r.inner.Record(record)

	// Record evidence (this is fast: ECDSA P-256 < 1ms).
	if record.Timestamp.IsZero() {
		record.Timestamp = time.Now()
	}
	r.evidence.RecordEvidence(record)
}
