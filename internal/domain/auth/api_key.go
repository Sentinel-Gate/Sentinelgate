package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/alexedwards/argon2id"
)

// ErrInvalidKey is returned when an API key is invalid (expired or revoked).
var ErrInvalidKey = errors.New("invalid api key")

// ErrUnknownHashType is returned when a stored hash has an unrecognized format.
var ErrUnknownHashType = errors.New("unknown hash type")

// APIKeyService validates API keys and returns identities.
type APIKeyService struct {
	store AuthStore
}

// NewAPIKeyService creates a new APIKeyService with the given store.
func NewAPIKeyService(store AuthStore) *APIKeyService {
	return &APIKeyService{store: store}
}

// Validate checks an API key and returns the associated identity.
// Returns ErrInvalidKey if key is invalid, expired, or revoked.
// Returns store-specific errors if key or identity doesn't exist.
//
// Supports both SHA-256 (direct lookup) and Argon2id (iteration) hashes.
func (s *APIKeyService) Validate(ctx context.Context, rawKey string) (*Identity, error) {
	// First try direct SHA-256 lookup (fast path for YAML-seeded keys)
	keyHash := HashKey(rawKey)
	apiKey, err := s.store.GetAPIKey(ctx, keyHash)
	if err == nil {
		return s.validateAndResolve(ctx, apiKey)
	}

	// Fallback: iterate all keys and verify (supports Argon2id hashes)
	allKeys, err := s.store.ListAPIKeys(ctx)
	if err != nil {
		return nil, ErrInvalidKey
	}

	for _, candidate := range allKeys {
		match, verifyErr := VerifyKey(rawKey, candidate.Key)
		if verifyErr != nil {
			continue
		}
		if match {
			return s.validateAndResolve(ctx, candidate)
		}
	}

	return nil, ErrInvalidKey
}

// validateAndResolve checks revocation/expiry and returns the identity.
func (s *APIKeyService) validateAndResolve(ctx context.Context, apiKey *APIKey) (*Identity, error) {
	if apiKey.Revoked {
		return nil, ErrInvalidKey
	}
	if apiKey.IsExpired() {
		return nil, ErrInvalidKey
	}
	identity, err := s.store.GetIdentity(ctx, apiKey.IdentityID)
	if err != nil {
		return nil, err
	}
	return identity, nil
}

// HashKey returns the SHA-256 hex hash of the raw key.
// Deprecated: Use HashKeyArgon2id for new keys. This is kept for backward compatibility.
func HashKey(rawKey string) string {
	hash := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(hash[:])
}

// argon2idParams defines OWASP minimum parameters for Argon2id.
// Memory: 46 MiB, Iterations: 1, Parallelism: 1
var argon2idParams = &argon2id.Params{
	Memory:      47 * 1024, // 47 MiB (OWASP minimum: 46 MiB)
	Iterations:  1,
	Parallelism: 1,
	SaltLength:  16,
	KeyLength:   32,
}

// HashKeyArgon2id returns an Argon2id hash of the raw key in PHC format.
// The hash includes a random salt and uses OWASP minimum parameters.
// Format: $argon2id$v=19$m=47104,t=1,p=1$<salt>$<hash>
func HashKeyArgon2id(rawKey string) (string, error) {
	return argon2id.CreateHash(rawKey, argon2idParams)
}

// DetectHashType identifies the hash algorithm used for a stored hash.
// Returns "argon2id" for PHC format, "sha256" for prefixed or bare hex,
// "unknown" for unrecognized formats.
func DetectHashType(storedHash string) string {
	if strings.HasPrefix(storedHash, "$argon2id$") {
		return "argon2id"
	}
	if strings.HasPrefix(storedHash, "sha256:") {
		return "sha256"
	}
	// Legacy bare SHA-256 hex is exactly 64 hex characters
	if len(storedHash) == 64 && isHexString(storedHash) {
		return "sha256"
	}
	return "unknown"
}

// isHexString checks if a string contains only valid hexadecimal characters.
func isHexString(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// VerifyKey verifies a raw key against a stored hash.
// Supports Argon2id (PHC format), SHA-256 prefixed, and legacy bare SHA-256 hex.
// Returns (true, nil) if match, (false, nil) if no match,
// (false, ErrUnknownHashType) for unrecognized hash formats.
func VerifyKey(rawKey, storedHash string) (bool, error) {
	hashType := DetectHashType(storedHash)

	switch hashType {
	case "argon2id":
		match, err := safeArgon2idCompare(rawKey, storedHash)
		if err != nil {
			return false, err
		}
		return match, nil

	case "sha256":
		// Extract the actual hash value
		var expectedHash string
		if strings.HasPrefix(storedHash, "sha256:") {
			expectedHash = strings.TrimPrefix(storedHash, "sha256:")
		} else {
			expectedHash = storedHash // legacy bare hex
		}

		// Compute hash of provided key
		computedHash := HashKey(rawKey)

		// Use constant-time comparison to prevent timing attacks
		match := subtle.ConstantTimeCompare([]byte(computedHash), []byte(expectedHash)) == 1
		return match, nil

	default:
		return false, ErrUnknownHashType
	}
}

// safeArgon2idCompare wraps argon2id.ComparePasswordAndHash with panic recovery.
// The underlying argon2 library panics on malformed Argon2id hashes with invalid
// parameters (e.g., t=0 rounds, p=0 parallelism). This function catches those panics
// and converts them to errors instead, ensuring VerifyKey never panics.
func safeArgon2idCompare(rawKey, storedHash string) (match bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			match = false
			err = fmt.Errorf("invalid argon2id hash parameters: %v", r)
		}
	}()
	return argon2id.ComparePasswordAndHash(rawKey, storedHash)
}
