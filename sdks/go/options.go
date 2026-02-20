package sentinelgate

import (
	"net/http"
	"time"
)

// Option is a functional option for configuring a Client.
type Option func(*Client)

// WithServerAddr sets the SentinelGate server address.
// If not set, defaults to the SENTINELGATE_SERVER_ADDR environment variable.
func WithServerAddr(addr string) Option {
	return func(c *Client) {
		c.serverAddr = addr
	}
}

// WithAPIKey sets the API key for authenticating with the SentinelGate server.
// If not set, defaults to the SENTINELGATE_API_KEY environment variable.
func WithAPIKey(key string) Option {
	return func(c *Client) {
		c.apiKey = key
	}
}

// WithDefaultProtocol sets the default protocol for evaluation requests.
// If not set, defaults to "sdk".
func WithDefaultProtocol(protocol string) Option {
	return func(c *Client) {
		c.defaultProtocol = protocol
	}
}

// WithFailMode sets the fail mode when the server is unreachable.
// Valid values are "open" (allow on failure) and "closed" (deny on failure).
// If not set, defaults to the SENTINELGATE_FAIL_MODE environment variable or "open".
func WithFailMode(mode string) Option {
	return func(c *Client) {
		c.failMode = mode
	}
}

// WithTimeout sets the HTTP request timeout.
// If not set, defaults to 5 seconds.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		c.timeout = d
	}
}

// WithCacheTTL sets the cache entry time-to-live.
// If not set, defaults to the SENTINELGATE_CACHE_TTL environment variable or 5 seconds.
func WithCacheTTL(d time.Duration) Option {
	return func(c *Client) {
		c.cacheTTL = d
	}
}

// WithCacheMaxSize sets the maximum number of entries in the cache.
// If not set, defaults to 1000.
func WithCacheMaxSize(n int) Option {
	return func(c *Client) {
		c.cacheMaxSize = n
	}
}

// WithHTTPClient sets a custom http.Client for making requests.
// This is useful for testing, proxying, or custom transport configurations.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		c.httpClient = hc
	}
}

// WithIdentityName sets the default identity name for evaluation requests.
// This is used when the EvaluateRequest does not specify an IdentityName.
func WithIdentityName(name string) Option {
	return func(c *Client) {
		c.identityName = name
	}
}

// WithIdentityRoles sets the default identity roles for evaluation requests.
// These are used when the EvaluateRequest does not specify IdentityRoles.
func WithIdentityRoles(roles []string) Option {
	return func(c *Client) {
		c.identityRoles = roles
	}
}
