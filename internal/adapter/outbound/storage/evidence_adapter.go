package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	ev "github.com/Sentinel-Gate/Sentinelgate/internal/domain/evidence"
	domainstorage "github.com/Sentinel-Gate/Sentinelgate/internal/domain/storage"
)

const evidenceKeyPrefix = "evidence/"

// VersionedEvidenceStore adapts VersionedStore to be used as an EvidenceStore.
// Each evidence record is stored as a versioned value with key "evidence/{id}".
// The chain metadata (last hash, sequence number) is stored under "evidence/_chain".
type VersionedEvidenceStore struct {
	store domainstorage.VersionedStore
}

// NewVersionedEvidenceStore creates an evidence store backed by a VersionedStore.
func NewVersionedEvidenceStore(store domainstorage.VersionedStore) *VersionedEvidenceStore {
	return &VersionedEvidenceStore{store: store}
}

// Append writes a signed evidence record to the versioned store.
func (s *VersionedEvidenceStore) Append(record ev.Record) error {
	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal evidence record: %w", err)
	}

	ctx := context.Background()
	key := evidenceKeyPrefix + record.ID

	return s.store.Put(ctx, key, domainstorage.Value{
		Data:      data,
		UpdatedAt: record.Timestamp,
		Metadata: map[string]string{
			"chain_hash": record.ChainHash,
			"signer":     record.Signature.Signer,
		},
	})
}

// Close is a no-op; the underlying store manages its own lifecycle.
func (s *VersionedEvidenceStore) Close() error {
	return nil
}

// GetRecord retrieves a specific evidence record by ID.
func (s *VersionedEvidenceStore) GetRecord(ctx context.Context, id string) (ev.Record, error) {
	val, err := s.store.Get(ctx, evidenceKeyPrefix+id)
	if err != nil {
		return ev.Record{}, err
	}

	var record ev.Record
	if err := json.Unmarshal(val.Data, &record); err != nil {
		return ev.Record{}, fmt.Errorf("unmarshal evidence record: %w", err)
	}
	return record, nil
}

// ListRecords returns all evidence record IDs, ordered by storage time.
func (s *VersionedEvidenceStore) ListRecords(ctx context.Context) ([]string, error) {
	keys, err := s.store.List(ctx, "evidence/")
	if err != nil {
		return nil, err
	}

	// Filter out the chain metadata key.
	var ids []string
	for _, k := range keys {
		if k != "evidence/_chain" {
			ids = append(ids, k[len("evidence/"):])
		}
	}
	return ids, nil
}

// SaveChainState persists the chain hash and sequence number for recovery on restart.
type chainState struct {
	PrevHash string `json:"prev_hash"`
	SeqNum   uint64 `json:"seq_num,string"`
}

func (s *VersionedEvidenceStore) SaveChainState(ctx context.Context, prevHash string, seqNum uint64) error {
	data, err := json.Marshal(chainState{
		PrevHash: prevHash,
		SeqNum:   seqNum,
	})
	if err != nil {
		return fmt.Errorf("marshal chain state: %w", err)
	}

	return s.store.Put(ctx, "evidence/_chain", domainstorage.Value{
		Data:      data,
		UpdatedAt: time.Now().UTC(),
	})
}

// LoadChainState loads the persisted chain state. Returns ("", 0, nil) if no state exists.
func (s *VersionedEvidenceStore) LoadChainState(ctx context.Context) (prevHash string, seqNum uint64, err error) {
	val, err := s.store.Get(ctx, "evidence/_chain")
	if err != nil {
		var notFound *domainstorage.ErrNotFound
		if isNotFound(err, notFound) {
			return "", 0, nil
		}
		return "", 0, err
	}

	var cs chainState
	if err := json.Unmarshal(val.Data, &cs); err != nil {
		return "", 0, fmt.Errorf("unmarshal chain state: %w", err)
	}
	return cs.PrevHash, cs.SeqNum, nil
}

func isNotFound(err error, _ *domainstorage.ErrNotFound) bool {
	var notFound *domainstorage.ErrNotFound
	return errors.As(err, &notFound)
}
