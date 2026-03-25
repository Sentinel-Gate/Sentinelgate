package evidence

import (
	"testing"
	"time"
)

func TestEvidenceRecordTypes(t *testing.T) {
	now := time.Now().UTC()

	record := Record{
		Version:   "1.0",
		ID:        "ev-001",
		Timestamp: now,
		ChainHash: "sha256:abc123",
		Identity: IdentityInfo{
			UserID:   "user-42",
			Roles:    []string{"admin", "auditor"},
			KeyHash:  "sha256:keyhash",
			Protocol: "mcp",
		},
		Action: ActionInfo{
			Tool:          "read_file",
			Arguments:     map[string]interface{}{"path": "/etc/hosts"},
			Decision:      "allow",
			PolicyMatched: "rule-10",
		},
		Result: ResultInfo{
			LatencyMicros: 1500,
			Reason:        "policy matched",
		},
		Signature: SignatureInfo{
			Algorithm: "ed25519",
			Signer:    "signer-01",
			Value:     "c2lnbmF0dXJl",
		},
	}

	// Verify top-level fields.
	if record.Version != "1.0" {
		t.Errorf("Version = %q, want %q", record.Version, "1.0")
	}
	if record.ID != "ev-001" {
		t.Errorf("ID = %q, want %q", record.ID, "ev-001")
	}
	if !record.Timestamp.Equal(now) {
		t.Errorf("Timestamp = %v, want %v", record.Timestamp, now)
	}
	if record.ChainHash != "sha256:abc123" {
		t.Errorf("ChainHash = %q, want %q", record.ChainHash, "sha256:abc123")
	}

	// Verify Identity fields.
	if record.Identity.UserID != "user-42" {
		t.Errorf("Identity.UserID = %q, want %q", record.Identity.UserID, "user-42")
	}
	if len(record.Identity.Roles) != 2 || record.Identity.Roles[0] != "admin" {
		t.Errorf("Identity.Roles = %v, want [admin auditor]", record.Identity.Roles)
	}
	if record.Identity.KeyHash != "sha256:keyhash" {
		t.Errorf("Identity.KeyHash = %q, want %q", record.Identity.KeyHash, "sha256:keyhash")
	}
	if record.Identity.Protocol != "mcp" {
		t.Errorf("Identity.Protocol = %q, want %q", record.Identity.Protocol, "mcp")
	}

	// Verify Action fields.
	if record.Action.Tool != "read_file" {
		t.Errorf("Action.Tool = %q, want %q", record.Action.Tool, "read_file")
	}
	if record.Action.Decision != "allow" {
		t.Errorf("Action.Decision = %q, want %q", record.Action.Decision, "allow")
	}
	if record.Action.PolicyMatched != "rule-10" {
		t.Errorf("Action.PolicyMatched = %q, want %q", record.Action.PolicyMatched, "rule-10")
	}
	if record.Action.Arguments["path"] != "/etc/hosts" {
		t.Errorf("Action.Arguments[path] = %v, want /etc/hosts", record.Action.Arguments["path"])
	}

	// Verify Result fields.
	if record.Result.LatencyMicros != 1500 {
		t.Errorf("Result.LatencyMicros = %d, want 1500", record.Result.LatencyMicros)
	}
	if record.Result.Reason != "policy matched" {
		t.Errorf("Result.Reason = %q, want %q", record.Result.Reason, "policy matched")
	}

	// Verify Signature fields.
	if record.Signature.Algorithm != "ed25519" {
		t.Errorf("Signature.Algorithm = %q, want %q", record.Signature.Algorithm, "ed25519")
	}
	if record.Signature.Signer != "signer-01" {
		t.Errorf("Signature.Signer = %q, want %q", record.Signature.Signer, "signer-01")
	}
	if record.Signature.Value != "c2lnbmF0dXJl" {
		t.Errorf("Signature.Value = %q, want %q", record.Signature.Value, "c2lnbmF0dXJl")
	}
}

func TestChainState(t *testing.T) {
	// IdentityInfo with empty/nil roles represents a minimal identity.
	identity := IdentityInfo{
		UserID: "system",
	}

	if identity.UserID != "system" {
		t.Errorf("UserID = %q, want %q", identity.UserID, "system")
	}
	if identity.Roles != nil {
		t.Errorf("Roles = %v, want nil", identity.Roles)
	}

	// Verify that zero-value Record has sensible defaults.
	var zeroRecord Record
	if zeroRecord.Version != "" {
		t.Errorf("zero Version = %q, want empty", zeroRecord.Version)
	}
	if zeroRecord.ChainHash != "" {
		t.Errorf("zero ChainHash = %q, want empty", zeroRecord.ChainHash)
	}
	if zeroRecord.Timestamp != (time.Time{}) {
		t.Errorf("zero Timestamp = %v, want zero time", zeroRecord.Timestamp)
	}

	// Verify a chain linkage scenario: second record references first.
	first := Record{
		ID:        "ev-001",
		ChainHash: "",
		Version:   "1.0",
	}
	second := Record{
		ID:        "ev-002",
		ChainHash: "sha256:hash-of-ev-001",
		Version:   "1.0",
	}

	if first.ChainHash != "" {
		t.Errorf("first.ChainHash = %q, want empty (genesis)", first.ChainHash)
	}
	if second.ChainHash != "sha256:hash-of-ev-001" {
		t.Errorf("second.ChainHash = %q, want %q", second.ChainHash, "sha256:hash-of-ev-001")
	}
}
