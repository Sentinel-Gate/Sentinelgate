package sentinelgate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Client is the SentinelGate SDK client. It communicates with the SentinelGate
// Policy Decision API to evaluate actions against configured policies.
type Client struct {
	serverAddr      string
	apiKey          string
	defaultProtocol string
	failMode        string
	timeout         time.Duration
	httpClient      *http.Client
	identityName    string
	identityRoles   []string

	// Cache fields.
	cache        sync.Map
	cacheTTL     time.Duration
	cacheMaxSize int
	cacheCount   int64
	cacheMu      sync.Mutex

	logger *slog.Logger
}

// cacheEntry is a cached evaluation response with expiry.
type cacheEntry struct {
	response  *EvaluateResponse
	expiresAt time.Time
	createdAt time.Time
}

// NewClient creates a new SentinelGate SDK client.
// It reads configuration from SENTINELGATE_* environment variables by default.
// Options can be used to override the defaults.
func NewClient(opts ...Option) *Client {
	c := &Client{
		serverAddr:      os.Getenv("SENTINELGATE_SERVER_ADDR"),
		apiKey:          os.Getenv("SENTINELGATE_API_KEY"),
		defaultProtocol: envOrDefault("SENTINELGATE_PROTOCOL", "sdk"),
		failMode:        envOrDefault("SENTINELGATE_FAIL_MODE", "open"),
		timeout:         parseDurationEnv("SENTINELGATE_TIMEOUT", 5*time.Second),
		cacheTTL:        parseDurationEnv("SENTINELGATE_CACHE_TTL", 5*time.Second),
		cacheMaxSize:    parseIntEnv("SENTINELGATE_CACHE_MAX_SIZE", 1000),
		identityName:    os.Getenv("SENTINELGATE_IDENTITY_NAME"),
		identityRoles:   parseRolesEnv("SENTINELGATE_IDENTITY_ROLES"),
		logger:          slog.Default(),
	}

	for _, opt := range opts {
		opt(c)
	}

	if c.httpClient == nil {
		c.httpClient = &http.Client{
			Timeout: c.timeout,
		}
	}

	return c
}

// Evaluate sends a policy evaluation request to the SentinelGate server and
// returns the decision. On deny, it returns a *PolicyDeniedError. On
// approval_required, it polls for approval status. On server unreachable with
// fail_mode=open, it returns an allow response.
func (c *Client) Evaluate(ctx context.Context, req EvaluateRequest) (*EvaluateResponse, error) {
	// Fill defaults from client configuration.
	if req.Protocol == "" {
		req.Protocol = c.defaultProtocol
	}
	if req.IdentityName == "" {
		req.IdentityName = c.identityName
	}
	if len(req.IdentityRoles) == 0 {
		req.IdentityRoles = c.identityRoles
	}

	// Check cache.
	cacheKey := c.buildCacheKey(req)
	if resp, ok := c.getFromCache(cacheKey); ok {
		return resp, nil
	}

	// Send request.
	resp, err := c.doEvaluate(ctx, req)
	if err != nil {
		// Handle server unreachable.
		if isConnectionError(err) {
			if c.failMode == "closed" {
				return nil, &ServerUnreachableError{Cause: err}
			}
			// Fail open: return allow.
			c.logger.Warn("SentinelGate server unreachable, failing open",
				"server_addr", c.serverAddr,
				"error", err,
			)
			return &EvaluateResponse{
				Decision: DecisionAllow,
				Reason:   "server unreachable, fail-open",
			}, nil
		}
		return nil, err
	}

	// Handle decision.
	switch resp.Decision {
	case DecisionAllow:
		c.putInCache(cacheKey, resp)
		return resp, nil

	case DecisionDeny:
		return nil, &PolicyDeniedError{
			RuleID:    resp.RuleID,
			RuleName:  resp.RuleName,
			Reason:    resp.Reason,
			HelpURL:   resp.HelpURL,
			HelpText:  resp.HelpText,
			RequestID: resp.RequestID,
		}

	case DecisionApprovalRequired:
		// Poll for approval status.
		return c.pollApprovalStatus(ctx, resp.RequestID)

	default:
		return resp, nil
	}
}

// Check is a convenience method that evaluates a request and returns a boolean.
// It returns true if the action is allowed, false if denied.
// Unlike Evaluate, it does not return an error on policy denial.
func (c *Client) Check(ctx context.Context, req EvaluateRequest) (bool, error) {
	resp, err := c.Evaluate(ctx, req)
	if err != nil {
		var denied *PolicyDeniedError
		if errors.As(err, &denied) {
			return false, nil
		}
		return false, err
	}
	return resp.Decision == DecisionAllow, nil
}

// doEvaluate sends the HTTP request to the policy evaluation endpoint.
func (c *Client) doEvaluate(ctx context.Context, req EvaluateRequest) (*EvaluateResponse, error) {
	var resp EvaluateResponse
	err := c.doRequest(ctx, http.MethodPost, "/admin/api/v1/policy/evaluate", req, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// pollApprovalStatus polls the evaluation status endpoint until the decision
// changes from approval_required, or until the maximum number of polls is reached.
func (c *Client) pollApprovalStatus(ctx context.Context, requestID string) (*EvaluateResponse, error) {
	const (
		pollInterval = 2 * time.Second
		maxPolls     = 30
	)

	for i := 0; i < maxPolls; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(pollInterval):
		}

		var status StatusResponse
		path := fmt.Sprintf("/admin/api/v1/policy/evaluate/%s/status", requestID)
		err := c.doRequest(ctx, http.MethodGet, path, nil, &status)
		if err != nil {
			c.logger.Warn("approval status poll failed",
				"request_id", requestID,
				"error", err,
			)
			continue
		}

		switch status.Decision {
		case DecisionAllow:
			return &EvaluateResponse{
				Decision:  DecisionAllow,
				RequestID: requestID,
				Reason:    "approved",
			}, nil
		case DecisionDeny:
			return nil, &PolicyDeniedError{
				Reason:    "approval denied",
				RequestID: requestID,
			}
		}
		// Still approval_required, continue polling.
	}

	return nil, &ApprovalTimeoutError{RequestID: requestID}
}

// doRequest performs an HTTP request to the SentinelGate server.
func (c *Client) doRequest(ctx context.Context, method, path string, body any, result any) error {
	url := strings.TrimRight(c.serverAddr, "/") + path

	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if body != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	if c.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return &SentinelGateError{
			Code: fmt.Sprintf("HTTP_%d", httpResp.StatusCode),
			Err:  fmt.Errorf("server returned %d: %s", httpResp.StatusCode, string(respBody)),
		}
	}

	if result != nil {
		if err := json.Unmarshal(respBody, result); err != nil {
			return fmt.Errorf("failed to unmarshal response: %w", err)
		}
	}

	return nil
}

// buildCacheKey creates a cache key from the evaluation request.
// Key is based on action_type, action_name, and a hash of the arguments.
func (c *Client) buildCacheKey(req EvaluateRequest) string {
	h := sha256.New()
	if req.Arguments != nil {
		argBytes, _ := json.Marshal(req.Arguments)
		h.Write(argBytes)
	}
	argsHash := hex.EncodeToString(h.Sum(nil))[:16]
	return fmt.Sprintf("%s:%s:%s", req.ActionType, req.ActionName, argsHash)
}

// getFromCache retrieves a cached response if it exists and hasn't expired.
func (c *Client) getFromCache(key string) (*EvaluateResponse, bool) {
	val, ok := c.cache.Load(key)
	if !ok {
		return nil, false
	}
	entry := val.(*cacheEntry)
	if time.Now().After(entry.expiresAt) {
		c.cache.Delete(key)
		c.cacheMu.Lock()
		c.cacheCount--
		c.cacheMu.Unlock()
		return nil, false
	}
	return entry.response, true
}

// putInCache stores a response in the cache.
func (c *Client) putInCache(key string, resp *EvaluateResponse) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()

	// Best-effort eviction: if over max size, delete some expired entries.
	if c.cacheCount >= int64(c.cacheMaxSize) {
		now := time.Now()
		evicted := 0
		c.cache.Range(func(k, v any) bool {
			entry := v.(*cacheEntry)
			if now.After(entry.expiresAt) {
				c.cache.Delete(k)
				evicted++
			}
			// Stop after evicting enough or checking a batch.
			return evicted < 100
		})
		c.cacheCount -= int64(evicted)

		// If still over limit, evict oldest entries.
		if c.cacheCount >= int64(c.cacheMaxSize) {
			var oldest time.Time
			var oldestKey any
			c.cache.Range(func(k, v any) bool {
				entry := v.(*cacheEntry)
				if oldest.IsZero() || entry.createdAt.Before(oldest) {
					oldest = entry.createdAt
					oldestKey = k
				}
				return true
			})
			if oldestKey != nil {
				c.cache.Delete(oldestKey)
				c.cacheCount--
			}
		}
	}

	c.cache.Store(key, &cacheEntry{
		response:  resp,
		expiresAt: time.Now().Add(c.cacheTTL),
		createdAt: time.Now(),
	})
	c.cacheCount++
}

// isConnectionError determines if an error is a connection-level error
// (server unreachable, connection refused, timeout, etc.).
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}

	// Check for SentinelGateError (HTTP errors are not connection errors).
	var sgErr *SentinelGateError
	if errors.As(err, &sgErr) {
		return false
	}

	// All other errors from http.Client.Do are connection errors
	// (DNS resolution, connection refused, TLS handshake, timeouts).
	return true
}

// Helper functions for env var parsing.

func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func parseDurationEnv(key string, defaultVal time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return defaultVal
	}
	// Try parsing as seconds (integer).
	if secs, err := strconv.Atoi(v); err == nil {
		return time.Duration(secs) * time.Second
	}
	// Try parsing as duration string.
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	return defaultVal
}

func parseIntEnv(key string, defaultVal int) int {
	v := os.Getenv(key)
	if v == "" {
		return defaultVal
	}
	if n, err := strconv.Atoi(v); err == nil {
		return n
	}
	return defaultVal
}

func parseRolesEnv(key string) []string {
	v := os.Getenv(key)
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	roles := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			roles = append(roles, p)
		}
	}
	return roles
}
