package runtime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPrepareBootstrap_CreatesDirs(t *testing.T) {
	t.Parallel()

	env, err := PrepareBootstrap(BootstrapConfig{
		ServerAddr: "http://localhost:8080",
		APIKey:     "sg_runtime_test",
		AgentID:    "test-agent-id",
	})
	if err != nil {
		t.Fatalf("PrepareBootstrap() error = %v", err)
	}
	defer Cleanup(env)

	// Verify root dir exists.
	if _, err := os.Stat(env.Dir); os.IsNotExist(err) {
		t.Error("bootstrap dir was not created")
	}

	// Verify prefix.
	base := filepath.Base(env.Dir)
	if !strings.HasPrefix(base, "sentinelgate-bootstrap-") {
		t.Errorf("dir name = %q, want sentinelgate-bootstrap-* prefix", base)
	}

	// Verify python subdir.
	if _, err := os.Stat(env.PythonDir); os.IsNotExist(err) {
		t.Error("python dir was not created")
	}
	if filepath.Base(env.PythonDir) != "python" {
		t.Errorf("python dir base = %q, want %q", filepath.Base(env.PythonDir), "python")
	}

	// Verify node subdir.
	if _, err := os.Stat(env.NodeDir); os.IsNotExist(err) {
		t.Error("node dir was not created")
	}
	if filepath.Base(env.NodeDir) != "node" {
		t.Errorf("node dir base = %q, want %q", filepath.Base(env.NodeDir), "node")
	}
}

func TestPrepareBootstrap_CustomDir(t *testing.T) {
	t.Parallel()

	customDir := t.TempDir()
	bootstrapDir := filepath.Join(customDir, "bootstrap")

	env, err := PrepareBootstrap(BootstrapConfig{
		ServerAddr:   "http://localhost:8080",
		APIKey:       "sg_runtime_test",
		AgentID:      "test-agent-id",
		BootstrapDir: bootstrapDir,
	})
	if err != nil {
		t.Fatalf("PrepareBootstrap() error = %v", err)
	}
	defer Cleanup(env)

	if env.Dir != bootstrapDir {
		t.Errorf("env.Dir = %q, want %q", env.Dir, bootstrapDir)
	}
}

func TestBuildEnvVars_AllVarsPresent(t *testing.T) {
	t.Parallel()

	env := &BootstrapEnv{
		Dir:       "/tmp/sg-test",
		PythonDir: "/tmp/sg-test/python",
		NodeDir:   "/tmp/sg-test/node",
	}
	cfg := BootstrapConfig{
		ServerAddr: "http://localhost:8080",
		APIKey:     "sg_runtime_abc123",
		AgentID:    "agent-uuid-123",
		CacheTTL:   10 * time.Second,
	}

	vars := BuildEnvVars(env, cfg)

	// Convert to map for easier assertions.
	varMap := make(map[string]string)
	for _, v := range vars {
		if idx := strings.IndexByte(v, '='); idx >= 0 {
			varMap[v[:idx]] = v[idx+1:]
		}
	}

	// Verify all required SENTINELGATE_* vars.
	if got := varMap["SENTINELGATE_SERVER_ADDR"]; got != "http://localhost:8080" {
		t.Errorf("SENTINELGATE_SERVER_ADDR = %q, want %q", got, "http://localhost:8080")
	}
	if got := varMap["SENTINELGATE_API_KEY"]; got != "sg_runtime_abc123" {
		t.Errorf("SENTINELGATE_API_KEY = %q, want %q", got, "sg_runtime_abc123")
	}
	if got := varMap["SENTINELGATE_AGENT_ID"]; got != "agent-uuid-123" {
		t.Errorf("SENTINELGATE_AGENT_ID = %q, want %q", got, "agent-uuid-123")
	}
	if got := varMap["SENTINELGATE_CACHE_TTL"]; got != "10" {
		t.Errorf("SENTINELGATE_CACHE_TTL = %q, want %q", got, "10")
	}
	// Default fail mode should be "open" when not set.
	if got := varMap["SENTINELGATE_FAIL_MODE"]; got != "open" {
		t.Errorf("SENTINELGATE_FAIL_MODE = %q, want %q", got, "open")
	}
	// Framework should be empty when not set.
	if got, ok := varMap["SENTINELGATE_FRAMEWORK"]; !ok {
		t.Error("SENTINELGATE_FRAMEWORK not present in env vars")
	} else if got != "" {
		t.Errorf("SENTINELGATE_FRAMEWORK = %q, want empty string", got)
	}

	// Verify PYTHONPATH contains bootstrap python dir.
	pythonPath := varMap["PYTHONPATH"]
	if !strings.Contains(pythonPath, "/tmp/sg-test/python") {
		t.Errorf("PYTHONPATH = %q, should contain /tmp/sg-test/python", pythonPath)
	}

	// Verify NODE_OPTIONS contains --require hook (always uses forward slashes).
	nodeOpts := varMap["NODE_OPTIONS"]
	expectedHook := "--require /tmp/sg-test/node/sentinelgate-hook.js"
	if !strings.Contains(nodeOpts, expectedHook) {
		t.Errorf("NODE_OPTIONS = %q, should contain %q", nodeOpts, expectedHook)
	}
	// Verify no backslashes in hook path (cross-platform consistency).
	if strings.Contains(nodeOpts, "\\") {
		t.Errorf("NODE_OPTIONS should use forward slashes, got %q", nodeOpts)
	}
}

func TestBuildEnvVars_DefaultCacheTTL(t *testing.T) {
	t.Parallel()

	env := &BootstrapEnv{
		Dir:       "/tmp/sg-test",
		PythonDir: "/tmp/sg-test/python",
		NodeDir:   "/tmp/sg-test/node",
	}
	cfg := BootstrapConfig{
		ServerAddr: "http://localhost:8080",
		APIKey:     "sg_runtime_abc123",
		AgentID:    "agent-uuid-123",
		// CacheTTL zero -> default 5.
	}

	vars := BuildEnvVars(env, cfg)
	varMap := toMap(vars)

	if got := varMap["SENTINELGATE_CACHE_TTL"]; got != "5" {
		t.Errorf("SENTINELGATE_CACHE_TTL = %q, want %q (default)", got, "5")
	}
}

func TestBuildEnvVars_PythonPathPrepend(t *testing.T) {
	// Set existing PYTHONPATH.
	t.Setenv("PYTHONPATH", "/existing/python/path")

	env := &BootstrapEnv{
		Dir:       "/tmp/sg-test",
		PythonDir: "/tmp/sg-test/python",
		NodeDir:   "/tmp/sg-test/node",
	}
	cfg := BootstrapConfig{
		ServerAddr: "http://localhost:8080",
		APIKey:     "test",
		AgentID:    "agent-id",
	}

	vars := BuildEnvVars(env, cfg)
	varMap := toMap(vars)

	pythonPath := varMap["PYTHONPATH"]
	// Bootstrap dir should be first (prepended).
	if !strings.HasPrefix(pythonPath, "/tmp/sg-test/python") {
		t.Errorf("PYTHONPATH should start with bootstrap dir, got %q", pythonPath)
	}
	// Existing path should still be present.
	if !strings.Contains(pythonPath, "/existing/python/path") {
		t.Errorf("PYTHONPATH should contain existing path, got %q", pythonPath)
	}
}

func TestBuildEnvVars_NodeOptionsAppend(t *testing.T) {
	// Set existing NODE_OPTIONS.
	t.Setenv("NODE_OPTIONS", "--max-old-space-size=4096")

	env := &BootstrapEnv{
		Dir:       "/tmp/sg-test",
		PythonDir: "/tmp/sg-test/python",
		NodeDir:   "/tmp/sg-test/node",
	}
	cfg := BootstrapConfig{
		ServerAddr: "http://localhost:8080",
		APIKey:     "test",
		AgentID:    "agent-id",
	}

	vars := BuildEnvVars(env, cfg)
	varMap := toMap(vars)

	nodeOpts := varMap["NODE_OPTIONS"]
	// Existing options should come first.
	if !strings.HasPrefix(nodeOpts, "--max-old-space-size=4096") {
		t.Errorf("NODE_OPTIONS should start with existing options, got %q", nodeOpts)
	}
	// Hook should be appended (always uses forward slashes).
	if !strings.Contains(nodeOpts, "--require /tmp/sg-test/node/sentinelgate-hook.js") {
		t.Errorf("NODE_OPTIONS should contain --require hook, got %q", nodeOpts)
	}
}

func TestMergeEnv_OverridesExisting(t *testing.T) {
	t.Parallel()

	parent := []string{
		"HOME=/home/user",
		"PATH=/usr/bin",
		"EXISTING_VAR=old",
	}
	bootstrap := []string{
		"EXISTING_VAR=new",
		"SENTINELGATE_API_KEY=sg_runtime_test",
	}

	result := MergeEnv(parent, bootstrap)

	varMap := toMap(result)
	if got := varMap["HOME"]; got != "/home/user" {
		t.Errorf("HOME = %q, want /home/user", got)
	}
	if got := varMap["EXISTING_VAR"]; got != "new" {
		t.Errorf("EXISTING_VAR = %q, want new (overridden)", got)
	}
	if got := varMap["SENTINELGATE_API_KEY"]; got != "sg_runtime_test" {
		t.Errorf("SENTINELGATE_API_KEY = %q, want sg_runtime_test", got)
	}
}

func TestMergeEnv_AddsNew(t *testing.T) {
	t.Parallel()

	parent := []string{"HOME=/home/user"}
	bootstrap := []string{"NEW_VAR=value"}

	result := MergeEnv(parent, bootstrap)

	varMap := toMap(result)
	if got := varMap["NEW_VAR"]; got != "value" {
		t.Errorf("NEW_VAR = %q, want value", got)
	}
	if len(result) != 2 {
		t.Errorf("result length = %d, want 2", len(result))
	}
}

func TestCleanup_RemovesDir(t *testing.T) {
	t.Parallel()

	env, err := PrepareBootstrap(BootstrapConfig{
		ServerAddr: "http://localhost:8080",
		APIKey:     "test",
		AgentID:    "agent-id",
	})
	if err != nil {
		t.Fatalf("PrepareBootstrap() error = %v", err)
	}

	dir := env.Dir
	if err := Cleanup(env); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}

	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Error("Cleanup() did not remove directory")
	}
}

func TestCleanup_NilEnv(t *testing.T) {
	t.Parallel()

	if err := Cleanup(nil); err != nil {
		t.Errorf("Cleanup(nil) error = %v", err)
	}
}

func TestCleanup_EmptyDir(t *testing.T) {
	t.Parallel()

	if err := Cleanup(&BootstrapEnv{}); err != nil {
		t.Errorf("Cleanup(empty) error = %v", err)
	}
}

func TestBuildEnvVars_FailModeAndFramework(t *testing.T) {
	t.Parallel()

	env := &BootstrapEnv{
		Dir:       "/tmp/sg-test",
		PythonDir: "/tmp/sg-test/python",
		NodeDir:   "/tmp/sg-test/node",
	}
	cfg := BootstrapConfig{
		ServerAddr: "http://localhost:8080",
		APIKey:     "sg_runtime_abc123",
		AgentID:    "agent-uuid-123",
		CacheTTL:   10 * time.Second,
		FailMode:   "closed",
		Framework:  "langchain",
	}

	vars := BuildEnvVars(env, cfg)
	varMap := toMap(vars)

	if got := varMap["SENTINELGATE_FAIL_MODE"]; got != "closed" {
		t.Errorf("SENTINELGATE_FAIL_MODE = %q, want %q", got, "closed")
	}
	if got := varMap["SENTINELGATE_FRAMEWORK"]; got != "langchain" {
		t.Errorf("SENTINELGATE_FRAMEWORK = %q, want %q", got, "langchain")
	}
}

func TestBuildEnvVarsWithCACert(t *testing.T) {
	t.Parallel()

	env := &BootstrapEnv{
		Dir:       "/tmp/sg-test",
		PythonDir: "/tmp/sg-test/python",
		NodeDir:   "/tmp/sg-test/node",
	}
	cfg := BootstrapConfig{
		ServerAddr: "http://localhost:8080",
		APIKey:     "sg_runtime_abc123",
		AgentID:    "agent-uuid-123",
		CacheTTL:   10 * time.Second,
		CACertPath: "/home/user/.sentinelgate/ca-cert.pem",
	}

	vars := BuildEnvVars(env, cfg)
	varMap := toMap(vars)

	// Proxy vars are always present (Layer 2). API key is embedded in URL.
	wantProxy := "http://sg:sg_runtime_abc123@localhost:8080"
	if got := varMap["HTTP_PROXY"]; got != wantProxy {
		t.Errorf("HTTP_PROXY = %q, want %q", got, wantProxy)
	}
	if got := varMap["HTTPS_PROXY"]; got != wantProxy {
		t.Errorf("HTTPS_PROXY = %q, want %q", got, wantProxy)
	}
	if got := varMap["NO_PROXY"]; got != "localhost,127.0.0.1" {
		t.Errorf("NO_PROXY = %q, want %q", got, "localhost,127.0.0.1")
	}

	// CA cert trust vars should point to the CA cert path.
	expectedCert := "/home/user/.sentinelgate/ca-cert.pem"
	if got := varMap["REQUESTS_CA_BUNDLE"]; got != expectedCert {
		t.Errorf("REQUESTS_CA_BUNDLE = %q, want %q", got, expectedCert)
	}
	if got := varMap["SSL_CERT_FILE"]; got != expectedCert {
		t.Errorf("SSL_CERT_FILE = %q, want %q", got, expectedCert)
	}
	if got := varMap["NODE_EXTRA_CA_CERTS"]; got != expectedCert {
		t.Errorf("NODE_EXTRA_CA_CERTS = %q, want %q", got, expectedCert)
	}
}

func TestBuildEnvVarsWithoutCACert(t *testing.T) {
	t.Parallel()

	env := &BootstrapEnv{
		Dir:       "/tmp/sg-test",
		PythonDir: "/tmp/sg-test/python",
		NodeDir:   "/tmp/sg-test/node",
	}
	cfg := BootstrapConfig{
		ServerAddr: "http://localhost:8080",
		APIKey:     "sg_runtime_abc123",
		AgentID:    "agent-uuid-123",
		CacheTTL:   10 * time.Second,
		// CACertPath intentionally empty — no TLS inspection.
	}

	vars := BuildEnvVars(env, cfg)
	varMap := toMap(vars)

	// Proxy vars should ALWAYS be present (Layer 2 outbound control). API key embedded.
	wantProxy := "http://sg:sg_runtime_abc123@localhost:8080"
	if got := varMap["HTTP_PROXY"]; got != wantProxy {
		t.Errorf("HTTP_PROXY = %q, want %q", got, wantProxy)
	}
	if got := varMap["HTTPS_PROXY"]; got != wantProxy {
		t.Errorf("HTTPS_PROXY = %q, want %q", got, wantProxy)
	}
	if got := varMap["NO_PROXY"]; got != "localhost,127.0.0.1" {
		t.Errorf("NO_PROXY = %q, want %q", got, "localhost,127.0.0.1")
	}

	// CA trust vars should NOT be present when CACertPath is empty.
	caTrustVars := []string{"REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS"}
	for _, name := range caTrustVars {
		if _, ok := varMap[name]; ok {
			t.Errorf("%s should not be present when CACertPath is empty, but got %q", name, varMap[name])
		}
	}
}

func TestBuildEnvVars_PythonSitePackages(t *testing.T) {
	t.Parallel()

	env := &BootstrapEnv{
		Dir:       "/tmp/sg-test",
		PythonDir: "/tmp/sg-test/python",
		NodeDir:   "/tmp/sg-test/node",
	}
	cfg := BootstrapConfig{
		ServerAddr: "http://localhost:8080",
		APIKey:     "test",
		AgentID:    "agent-id",
		PythonSitePackages: []string{
			"/opt/homebrew/lib/python3.12/site-packages",
			"/usr/local/lib/python3.12/site-packages",
		},
	}

	vars := BuildEnvVars(env, cfg)
	varMap := toMap(vars)

	pythonPath := varMap["PYTHONPATH"]
	// Bootstrap dir should come first.
	if !strings.HasPrefix(pythonPath, "/tmp/sg-test/python") {
		t.Errorf("PYTHONPATH should start with bootstrap dir, got %q", pythonPath)
	}
	// Site-packages should be present.
	if !strings.Contains(pythonPath, "/opt/homebrew/lib/python3.12/site-packages") {
		t.Errorf("PYTHONPATH should contain homebrew site-packages, got %q", pythonPath)
	}
	if !strings.Contains(pythonPath, "/usr/local/lib/python3.12/site-packages") {
		t.Errorf("PYTHONPATH should contain usr/local site-packages, got %q", pythonPath)
	}
}

// toMap converts a slice of KEY=VALUE strings to a map.
func toMap(vars []string) map[string]string {
	m := make(map[string]string, len(vars))
	for _, v := range vars {
		if idx := strings.IndexByte(v, '='); idx >= 0 {
			m[v[:idx]] = v[idx+1:]
		}
	}
	return m
}
