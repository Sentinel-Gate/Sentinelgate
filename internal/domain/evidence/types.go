// Package evidence defines domain types for cryptographic audit evidence.
// Evidence records are signed, hash-chained audit entries that provide
// tamper-proof proof of every action processed by SentinelGate.
package evidence

import (
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
)

// Record is a signed, hash-chained audit entry.
type Record struct {
	Version   string    `json:"version"`
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	ChainHash string    `json:"chain_hash"` // "sha256:<hex>" of previous record

	Identity IdentityInfo `json:"identity"`
	Action   ActionInfo   `json:"action"`
	Result   ResultInfo   `json:"result"`

	Signature SignatureInfo `json:"signature"`
}

// IdentityInfo captures who performed the action.
type IdentityInfo struct {
	UserID   string   `json:"user_id"`
	Roles    []string `json:"roles,omitempty"`
	KeyHash  string   `json:"api_key_hash,omitempty"`
	Protocol string   `json:"protocol,omitempty"`
}

// ActionInfo captures what was done.
type ActionInfo struct {
	Tool          string                 `json:"tool"`
	Arguments     map[string]interface{} `json:"arguments,omitempty"`
	Decision      string                 `json:"decision"`
	PolicyMatched string                 `json:"policy_matched,omitempty"`
}

// ResultInfo captures the outcome.
type ResultInfo struct {
	LatencyMicros int64  `json:"latency_micros"`
	Reason        string `json:"reason,omitempty"`
}

// SignatureInfo holds the cryptographic signature.
type SignatureInfo struct {
	Algorithm string `json:"algorithm"`
	Signer    string `json:"signer"`
	Value     string `json:"value"` // base64-encoded signature
}

// RecordFromAudit converts an audit.AuditRecord to the evidence record payload
// (without signature and chain_hash, which are added by the service).
func RecordFromAudit(ar audit.AuditRecord) Record {
	roles := ar.Roles

	return Record{
		Version:   "1.0",
		Timestamp: ar.Timestamp,
		Identity: IdentityInfo{
			UserID:   ar.IdentityName,
			Roles:    roles,
			Protocol: ar.Protocol,
		},
		Action: ActionInfo{
			Tool:          ar.ToolName,
			Arguments:     ar.ToolArguments,
			Decision:      ar.Decision,
			PolicyMatched: ar.RuleID,
		},
		Result: ResultInfo{
			LatencyMicros: ar.LatencyMicros,
			Reason:        ar.Reason,
		},
	}
}

// Signer signs evidence records.
type Signer interface {
	// Sign produces a signature for the given data bytes.
	Sign(data []byte) ([]byte, error)
	// SignerID returns a stable identifier for this signer instance.
	SignerID() string
	// Algorithm returns the signing algorithm name.
	Algorithm() string
	// PublicKeyPEM returns the PEM-encoded public key for verification.
	PublicKeyPEM() []byte
}

// Verifier verifies evidence record signatures.
type Verifier interface {
	// Verify checks a signature against data using the signer's public key.
	Verify(data []byte, signature []byte) (bool, error)
}
