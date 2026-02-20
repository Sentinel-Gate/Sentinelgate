// Package runtime provides bootstrap infrastructure for the sentinel-gate run command.
// It handles runtime API key generation, bootstrap directory creation, environment
// variable preparation, and registration of runtime keys with the SentinelGate server.
package runtime

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const (
	// runtimeKeyPrefix is the prefix for all runtime-generated API keys.
	runtimeKeyPrefix = "sg_runtime_"

	// runtimeKeyRandomBytes is the number of random bytes used (32 hex chars).
	runtimeKeyRandomBytes = 16
)

// GenerateRuntimeAPIKey generates a per-process API key for runtime bootstrap.
// It returns the plaintext key (for setting as env var) and its SHA-256 hash
// (for registering with the auth store).
//
// Key format: sg_runtime_ + 32 random hex characters (e.g., sg_runtime_a1b2c3d4...).
func GenerateRuntimeAPIKey() (plaintext string, sha256Hash string, err error) {
	b := make([]byte, runtimeKeyRandomBytes)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	plaintext = runtimeKeyPrefix + hex.EncodeToString(b)

	hash := sha256.Sum256([]byte(plaintext))
	sha256Hash = hex.EncodeToString(hash[:])

	return plaintext, sha256Hash, nil
}

// registrationResult holds the identity ID from a successful registration,
// needed for cleanup (revocation) on exit.
type registrationResult struct {
	IdentityID string
}

// createIdentityRequest is the JSON body for creating a runtime identity.
type createIdentityRequest struct {
	Name  string   `json:"name"`
	Roles []string `json:"roles"`
}

// createIdentityResponse is the JSON response from the identity creation endpoint.
type createIdentityResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// createKeyRequest is the JSON body for generating an API key via admin API.
type createKeyRequest struct {
	IdentityID string `json:"identity_id"`
	Name       string `json:"name"`
}

// createKeyResponse is the JSON response from the key generation endpoint.
type createKeyResponse struct {
	ID           string `json:"id"`
	CleartextKey string `json:"cleartext_key"`
}

// fetchCSRFToken obtains a CSRF token from the SentinelGate admin API by making
// a GET request and extracting the sentinel_csrf_token cookie from the response.
func fetchCSRFToken(serverAddr string) (token string, cookies []*http.Cookie, err error) {
	resp, err := http.Get(fmt.Sprintf("%s/admin/api/auth/status", serverAddr))
	if err != nil {
		return "", nil, fmt.Errorf("failed to fetch CSRF token: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	for _, c := range resp.Cookies() {
		if c.Name == "sentinel_csrf_token" {
			return c.Value, resp.Cookies(), nil
		}
	}
	return "", nil, fmt.Errorf("no CSRF token cookie in response")
}

// csrfPost performs an HTTP POST with CSRF token and cookies attached.
func csrfPost(url, csrfToken string, cookies []*http.Cookie, body []byte) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrfToken)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	return http.DefaultClient.Do(req)
}

// RegisterRuntimeKey registers a runtime identity and API key with the SentinelGate
// server via its admin API. It creates a runtime identity and generates a server-side
// API key.
//
// Returns the server-generated cleartext key (to use as SENTINELGATE_API_KEY) and
// the identity ID (for cleanup on exit). If registration fails, returns an error
// and the caller should fall back to the locally-generated key.
func RegisterRuntimeKey(serverAddr, agentID string) (cleartextKey string, result *registrationResult, err error) {
	// Step 0: Obtain CSRF token for state-changing requests.
	csrfToken, cookies, err := fetchCSRFToken(serverAddr)
	if err != nil {
		return "", nil, fmt.Errorf("failed to obtain CSRF token: %w", err)
	}

	// Step 1: Create a runtime identity.
	identityBody, err := json.Marshal(createIdentityRequest{
		Name:  fmt.Sprintf("runtime-%s", agentID),
		Roles: []string{"agent"},
	})
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal identity request: %w", err)
	}

	identityURL := fmt.Sprintf("%s/admin/api/identities", serverAddr)
	resp, err := csrfPost(identityURL, csrfToken, cookies, identityBody)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create runtime identity: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", nil, fmt.Errorf("identity creation returned %d: %s", resp.StatusCode, string(body))
	}

	var identityResp createIdentityResponse
	if err := json.NewDecoder(resp.Body).Decode(&identityResp); err != nil {
		return "", nil, fmt.Errorf("failed to decode identity response: %w", err)
	}

	// Step 2: Generate an API key for the runtime identity.
	keyBody, err := json.Marshal(createKeyRequest{
		IdentityID: identityResp.ID,
		Name:       fmt.Sprintf("runtime-key-%s", agentID),
	})
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal key request: %w", err)
	}

	keyURL := fmt.Sprintf("%s/admin/api/keys", serverAddr)
	keyResp, err := csrfPost(keyURL, csrfToken, cookies, keyBody)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate runtime key: %w", err)
	}
	defer keyResp.Body.Close()

	if keyResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(keyResp.Body)
		return "", nil, fmt.Errorf("key generation returned %d: %s", keyResp.StatusCode, string(body))
	}

	var keyResult createKeyResponse
	if err := json.NewDecoder(keyResp.Body).Decode(&keyResult); err != nil {
		return "", nil, fmt.Errorf("failed to decode key response: %w", err)
	}

	return keyResult.CleartextKey, &registrationResult{
		IdentityID: identityResp.ID,
	}, nil
}

// AgentRegistration holds the data needed to register an agent with the server.
type AgentRegistration struct {
	ID        string   `json:"id"`
	Command   string   `json:"command"`
	Args      []string `json:"args"`
	Framework string   `json:"framework,omitempty"`
	FailMode  string   `json:"fail_mode"`
	PID       int      `json:"pid,omitempty"`
}

// RegisterAgent registers a running agent process with the SentinelGate server
// via POST /admin/api/agents/register. This makes the agent visible in the admin UI.
func RegisterAgent(serverAddr string, reg AgentRegistration) error {
	csrfToken, cookies, err := fetchCSRFToken(serverAddr)
	if err != nil {
		return fmt.Errorf("failed to obtain CSRF token for agent registration: %w", err)
	}

	body, err := json.Marshal(reg)
	if err != nil {
		return fmt.Errorf("failed to marshal agent registration: %w", err)
	}

	url := fmt.Sprintf("%s/admin/api/agents/register", serverAddr)
	resp, err := csrfPost(url, csrfToken, cookies, body)
	if err != nil {
		return fmt.Errorf("failed to register agent: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("agent registration returned %d", resp.StatusCode)
	}
	return nil
}

// UnregisterAgent removes a running agent from the SentinelGate server registry
// via DELETE /admin/api/agents/{id}. Called on cleanup when the child process exits.
func UnregisterAgent(serverAddr, agentID string) error {
	csrfToken, cookies, err := fetchCSRFToken(serverAddr)
	if err != nil {
		return fmt.Errorf("failed to obtain CSRF token for agent unregistration: %w", err)
	}

	url := fmt.Sprintf("%s/admin/api/agents/%s", serverAddr, agentID)
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create unregister request: %w", err)
	}
	req.Header.Set("X-CSRF-Token", csrfToken)
	for _, c := range cookies {
		req.AddCookie(c)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to unregister agent: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("agent unregistration returned %d", resp.StatusCode)
	}
	return nil
}

// RevokeRuntimeKey revokes the runtime identity and its keys by deleting the
// identity via the admin API. This is called on cleanup when the child process exits.
func RevokeRuntimeKey(serverAddr string, identityID string) error {
	// Obtain CSRF token for the DELETE request.
	csrfToken, cookies, err := fetchCSRFToken(serverAddr)
	if err != nil {
		return fmt.Errorf("failed to obtain CSRF token for revocation: %w", err)
	}

	revokeURL := fmt.Sprintf("%s/admin/api/identities/%s", serverAddr, identityID)
	req, err := http.NewRequest(http.MethodDelete, revokeURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create revoke request: %w", err)
	}
	req.Header.Set("X-CSRF-Token", csrfToken)
	for _, c := range cookies {
		req.AddCookie(c)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to revoke runtime identity: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("identity revocation returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
