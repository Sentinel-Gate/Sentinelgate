package runtime

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// BootstrapConfig holds the configuration needed to prepare the bootstrap environment.
type BootstrapConfig struct {
	// ServerAddr is the SentinelGate server address (e.g., "http://localhost:8080").
	ServerAddr string

	// APIKey is the plaintext runtime API key for the child process.
	APIKey string

	// AgentID is the unique identifier for this agent process (UUID).
	AgentID string

	// CacheTTL is the LRU cache TTL for recently-allowed patterns.
	CacheTTL time.Duration

	// FailMode controls behavior when the SentinelGate server is unreachable.
	// Valid values: "open" (allow, default) or "closed" (deny).
	FailMode string

	// Framework is the detected AI framework name (e.g., "langchain", "crewai").
	// May be empty if no framework was detected.
	Framework string

	// CACertPath is the path to the SentinelGate TLS inspection CA certificate.
	// When non-empty, BuildEnvVars injects CA cert trust environment variables
	// so child processes accept the MITM certificate for HTTPS content inspection.
	// HTTP_PROXY/HTTPS_PROXY are always set regardless of CACertPath.
	CACertPath string

	// SkipNodeOptions skips setting NODE_OPTIONS when true. Used for:
	//   - Bun binaries (e.g. Claude Code) that use PreToolUse hooks instead
	//   - Gemini CLI which uses MCP-level protection (tools.exclude + MCP proxy)
	SkipNodeOptions bool

	// PythonSitePackages contains site-packages directories detected from
	// the target Python interpreter. These are appended to PYTHONPATH so
	// that pip-installed packages remain importable after bootstrap injection.
	PythonSitePackages []string

	// BootstrapDir overrides the temp directory (for testing). If empty,
	// a temp directory is created automatically.
	BootstrapDir string
}

// BootstrapEnv holds the paths created by PrepareBootstrap.
type BootstrapEnv struct {
	// Dir is the root bootstrap temp directory.
	Dir string

	// PythonDir is the directory containing sitecustomize.py.
	PythonDir string

	// NodeDir is the directory containing the Node.js require hook.
	NodeDir string
}

// PrepareBootstrap creates a temporary bootstrap directory with subdirectories
// for Python and Node.js instrumentation hooks. It writes the embedded
// Python sitecustomize.py and Node.js sentinelgate-hook.js to their respective
// subdirectories.
func PrepareBootstrap(cfg BootstrapConfig) (*BootstrapEnv, error) {
	var dir string
	var err error

	if cfg.BootstrapDir != "" {
		dir = cfg.BootstrapDir
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create bootstrap dir: %w", err)
		}
	} else {
		dir, err = os.MkdirTemp("", "sentinelgate-bootstrap-*")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp dir: %w", err)
		}
	}

	pythonDir := filepath.Join(dir, "python")
	if err := os.MkdirAll(pythonDir, 0755); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("failed to create python dir: %w", err)
	}

	// Write embedded Python sitecustomize.py to python dir.
	if err := WritePythonBootstrap(pythonDir); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("failed to write python bootstrap: %w", err)
	}

	nodeDir := filepath.Join(dir, "node")
	if err := os.MkdirAll(nodeDir, 0755); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("failed to create node dir: %w", err)
	}

	// Write embedded Node.js sentinelgate-hook.js to node dir.
	if err := WriteNodeBootstrap(nodeDir); err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("failed to write node bootstrap: %w", err)
	}

	return &BootstrapEnv{
		Dir:       dir,
		PythonDir: pythonDir,
		NodeDir:   nodeDir,
	}, nil
}

// BuildEnvVars returns the environment variables that should be set on the child
// process for SentinelGate runtime protection. The returned slice contains
// KEY=VALUE strings suitable for exec.Cmd.Env.
//
// Variables set:
//   - SENTINELGATE_SERVER_ADDR: SentinelGate server address
//   - SENTINELGATE_API_KEY: Runtime API key (plaintext)
//   - SENTINELGATE_AGENT_ID: Unique agent process ID
//   - SENTINELGATE_CACHE_TTL: LRU cache TTL in seconds
//   - SENTINELGATE_FAIL_MODE: Fail mode ("open" or "closed")
//   - SENTINELGATE_FRAMEWORK: Detected AI framework name (may be empty)
//   - PYTHONPATH: Prepended with Python bootstrap dir
//   - NODE_OPTIONS: Appended with --require for Node.js hook
//
// Always set (Layer 2 outbound control):
//   - HTTP_PROXY: Routes HTTP traffic through SentinelGate
//   - HTTPS_PROXY: Routes HTTPS traffic through SentinelGate (CONNECT tunnel)
//   - NO_PROXY: Excludes localhost from proxying (prevents loops)
//
// When CACertPath is set (TLS inspection CA available):
//   - REQUESTS_CA_BUNDLE: Python requests library CA trust
//   - SSL_CERT_FILE: Python httpx / general SSL CA trust
//   - NODE_EXTRA_CA_CERTS: Node.js CA trust
func BuildEnvVars(env *BootstrapEnv, cfg BootstrapConfig) []string {
	// Default fail mode to "open" if not specified.
	failMode := cfg.FailMode
	if failMode == "" {
		failMode = string(FailModeOpen)
	}

	vars := []string{
		fmt.Sprintf("SENTINELGATE_SERVER_ADDR=%s", cfg.ServerAddr),
		fmt.Sprintf("SENTINELGATE_API_KEY=%s", cfg.APIKey),
		fmt.Sprintf("SENTINELGATE_AGENT_ID=%s", cfg.AgentID),
		fmt.Sprintf("SENTINELGATE_CACHE_TTL=%d", cacheTTLSeconds(cfg.CacheTTL)),
		fmt.Sprintf("SENTINELGATE_FAIL_MODE=%s", failMode),
		fmt.Sprintf("SENTINELGATE_FRAMEWORK=%s", cfg.Framework),
	}

	// PYTHONPATH: prepend bootstrap python dir, then append site-packages
	// paths detected from the target Python interpreter, then any existing
	// PYTHONPATH. This ensures pip-installed packages remain importable
	// even on non-standard Python installs (Homebrew, virtualenvs).
	pythonPathParts := []string{env.PythonDir}
	if len(cfg.PythonSitePackages) > 0 {
		pythonPathParts = append(pythonPathParts, cfg.PythonSitePackages...)
	}
	if existing := os.Getenv("PYTHONPATH"); existing != "" {
		pythonPathParts = append(pythonPathParts, existing)
	}
	vars = append(vars, fmt.Sprintf("PYTHONPATH=%s", strings.Join(pythonPathParts, string(os.PathListSeparator))))

	// NODE_OPTIONS: append --require hook to existing NODE_OPTIONS.
	// Skip for Bun binaries (e.g. Claude Code) that use PreToolUse hooks instead.
	if !cfg.SkipNodeOptions {
		hookPath := filepath.Join(env.NodeDir, "sentinelgate-hook.js")
		nodeOpts := fmt.Sprintf("--require %s", hookPath)
		if existing := os.Getenv("NODE_OPTIONS"); existing != "" {
			nodeOpts = existing + " " + nodeOpts
		}
		vars = append(vars, fmt.Sprintf("NODE_OPTIONS=%s", nodeOpts))
	}

	// Always route agent HTTP traffic through SentinelGate's HTTP Gateway
	// for outbound control (Layer 2). HTTPS without TLS inspection uses
	// CONNECT tunneling — the proxy sees the destination but not the content.
	// NO_PROXY prevents loops (agent → proxy → proxy → ...).
	//
	// The API key is embedded in the proxy URL as userinfo (http://sg:<key>@host:port).
	// HTTP clients automatically send Proxy-Authorization: Basic base64("sg:<key>")
	// which the gateway auth middleware extracts for authentication.
	proxyURL := buildProxyURL(cfg.ServerAddr, cfg.APIKey)
	vars = append(vars,
		fmt.Sprintf("HTTP_PROXY=%s", proxyURL),
		fmt.Sprintf("HTTPS_PROXY=%s", proxyURL),
		"NO_PROXY=localhost,127.0.0.1",
	)

	// When TLS inspection CA is available, inject CA trust env vars so child
	// processes accept the MITM certificate for full HTTPS content inspection.
	if cfg.CACertPath != "" {
		vars = append(vars,
			fmt.Sprintf("REQUESTS_CA_BUNDLE=%s", cfg.CACertPath),
			fmt.Sprintf("SSL_CERT_FILE=%s", cfg.CACertPath),
			fmt.Sprintf("NODE_EXTRA_CA_CERTS=%s", cfg.CACertPath),
		)
	}

	return vars
}

// MergeEnv merges bootstrap env vars into the parent environment. Bootstrap
// vars override any existing vars with the same name.
func MergeEnv(parentEnv, bootstrapVars []string) []string {
	// Build a map of bootstrap var names for quick lookup.
	overrides := make(map[string]string, len(bootstrapVars))
	for _, v := range bootstrapVars {
		if idx := strings.IndexByte(v, '='); idx >= 0 {
			overrides[v[:idx]] = v
		}
	}

	// Copy parent env, replacing any vars that are overridden.
	result := make([]string, 0, len(parentEnv)+len(bootstrapVars))
	seen := make(map[string]bool, len(bootstrapVars))
	for _, v := range parentEnv {
		if idx := strings.IndexByte(v, '='); idx >= 0 {
			name := v[:idx]
			if override, ok := overrides[name]; ok {
				result = append(result, override)
				seen[name] = true
				continue
			}
		}
		result = append(result, v)
	}

	// Add any bootstrap vars that weren't in the parent env.
	for _, v := range bootstrapVars {
		if idx := strings.IndexByte(v, '='); idx >= 0 {
			name := v[:idx]
			if !seen[name] {
				result = append(result, v)
			}
		}
	}

	return result
}

// Cleanup removes the bootstrap temporary directory and all its contents.
func Cleanup(env *BootstrapEnv) error {
	if env == nil || env.Dir == "" {
		return nil
	}
	return os.RemoveAll(env.Dir)
}

// buildProxyURL embeds the API key as credentials in the proxy URL.
// Input:  http://localhost:8080, sg_xxx → http://sg:sg_xxx@localhost:8080
// HTTP clients will then send Proxy-Authorization: Basic base64("sg:sg_xxx").
func buildProxyURL(serverAddr, apiKey string) string {
	if apiKey == "" {
		return serverAddr
	}
	u, err := url.Parse(serverAddr)
	if err != nil {
		return serverAddr
	}
	u.User = url.UserPassword("sg", apiKey)
	return u.String()
}

// cacheTTLSeconds returns the cache TTL as whole seconds, defaulting to 5
// if the duration is zero.
func cacheTTLSeconds(d time.Duration) int {
	if d == 0 {
		return 5
	}
	return int(d.Seconds())
}
