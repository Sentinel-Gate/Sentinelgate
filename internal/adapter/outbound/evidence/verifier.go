package evidence

import (
	"bufio"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"

	ev "github.com/Sentinel-Gate/Sentinelgate/internal/domain/evidence"
)

// VerifyResult is the outcome of verifying an evidence file.
type VerifyResult struct {
	TotalRecords    int
	ValidSignatures int
	InvalidSigs     int
	ChainValid      bool
	PartialChain    bool   // true when the first record doesn't start at genesis
	ChainBreakAt    int    // -1 if chain is valid, else index of first break
	FirstError      string // first error message encountered
}

// VerifyFile reads an evidence file and checks all signatures and the hash chain.
func VerifyFile(path string, keyPath string) (*VerifyResult, error) {
	verifier, err := NewECDSAVerifierFromKeyFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("load verification key: %w", err)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open evidence file: %w", err)
	}
	defer f.Close()

	return verifyFromReader(f, verifier)
}

// VerifyFileWithPubKey reads an evidence file and verifies using a PEM public key.
func VerifyFileWithPubKey(path string, pubKeyPEM []byte) (*VerifyResult, error) {
	verifier, err := NewECDSAVerifier(pubKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open evidence file: %w", err)
	}
	defer f.Close()

	return verifyFromReader(f, verifier)
}

func verifyFromReader(r io.Reader, verifier *ECDSAVerifier) (*VerifyResult, error) {
	result := &VerifyResult{ChainValid: true, ChainBreakAt: -1}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024) // 1MB max line

	var prevHash string
	idx := 0

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var record ev.Record
		if err := json.Unmarshal(line, &record); err != nil {
			result.InvalidSigs++
			if result.FirstError == "" {
				result.FirstError = fmt.Sprintf("line %d: invalid JSON: %v", idx+1, err)
			}
			idx++
			continue
		}
		result.TotalRecords++

		// Verify signature: sign payload is the record without the signature field.
		payload, err := canonicalPayload(record)
		if err != nil {
			result.InvalidSigs++
			if result.FirstError == "" {
				result.FirstError = fmt.Sprintf("record %s: canonical payload error: %v", record.ID, err)
			}
			idx++
			continue
		}

		sigBytes, err := base64.StdEncoding.DecodeString(record.Signature.Value)
		if err != nil {
			result.InvalidSigs++
			if result.FirstError == "" {
				result.FirstError = fmt.Sprintf("record %s: invalid base64 signature", record.ID)
			}
			idx++
			continue
		}

		valid, verifyErr := verifier.Verify(payload, sigBytes)
		if verifyErr != nil {
			result.InvalidSigs++
			if result.FirstError == "" {
				result.FirstError = fmt.Sprintf("record %s: verification error: %v", record.ID, verifyErr)
			}
			idx++
			continue
		}
		if valid {
			result.ValidSignatures++
		} else {
			result.InvalidSigs++
			if result.FirstError == "" {
				result.FirstError = fmt.Sprintf("record %s: signature verification failed", record.ID)
			}
		}

		// Verify hash chain.
		if idx == 0 {
			// First record: ideally chain_hash is "sha256:genesis".
			// When verifying a partial chain (e.g. JSONL dual-write started
			// mid-session), the first record may reference a prior record
			// not in this file — that is valid, we just can't verify the link.
			if record.ChainHash != "sha256:genesis" {
				result.PartialChain = true
			}
		} else {
			// Subsequent records: chain_hash should match SHA-256 of previous record
			expectedHash := "sha256:" + prevHash
			if record.ChainHash != expectedHash {
				if result.ChainValid {
					result.ChainValid = false
					result.ChainBreakAt = idx
				}
				if result.FirstError == "" {
					result.FirstError = fmt.Sprintf("record %s: chain break at index %d (expected %s, got %s)", record.ID, idx, expectedHash, record.ChainHash)
				}
			}
		}

		// Compute hash of this record for the next chain link.
		h := sha256.Sum256(line)
		prevHash = fmt.Sprintf("%x", h)
		idx++
	}

	if err := scanner.Err(); err != nil {
		return result, fmt.Errorf("scan error: %w", err)
	}

	return result, nil
}

// canonicalPayload produces the signing payload for a record.
// It serializes the record with the signature value cleared to get deterministic bytes.
func canonicalPayload(r ev.Record) ([]byte, error) {
	// Clear signature for canonical form.
	r.Signature.Value = ""
	return json.Marshal(r)
}
