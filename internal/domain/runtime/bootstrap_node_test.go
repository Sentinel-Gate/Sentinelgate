package runtime

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWriteNodeBootstrap_CreatesFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	if err := WriteNodeBootstrap(dir); err != nil {
		t.Fatalf("WriteNodeBootstrap() error = %v", err)
	}

	dest := filepath.Join(dir, "sentinelgate-hook.js")
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("stat sentinelgate-hook.js: %v", err)
	}

	if info.Size() == 0 {
		t.Error("sentinelgate-hook.js is empty")
	}

	// Verify file is readable.
	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read sentinelgate-hook.js: %v", err)
	}

	if len(data) == 0 {
		t.Error("sentinelgate-hook.js content is empty")
	}
}

func TestNodeHookEmbedded_NonEmpty(t *testing.T) {
	t.Parallel()

	if len(nodeHook) == 0 {
		t.Fatal("embedded nodeHook is empty")
	}
}

func TestNodeHookEmbedded_ContainsServerAddr(t *testing.T) {
	t.Parallel()

	content := string(nodeHook)
	if !strings.Contains(content, "SENTINELGATE_SERVER_ADDR") {
		t.Error("embedded nodeHook does not contain SENTINELGATE_SERVER_ADDR")
	}
}

func TestNodeHookEmbedded_ContainsKeyPatterns(t *testing.T) {
	t.Parallel()

	content := string(nodeHook)
	patterns := []string{
		"child_process",
		"_sgEvaluateSync",
		"_SgLRUCache",
		"_SgAuditBuffer",
		"_sgPollApprovalSync",
		"/admin/api/v1/policy/evaluate",
	}
	for _, p := range patterns {
		if !strings.Contains(content, p) {
			t.Errorf("embedded nodeHook missing pattern: %q", p)
		}
	}
}

func TestWriteNodeBootstrap_FilePermissions(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	if err := WriteNodeBootstrap(dir); err != nil {
		t.Fatalf("WriteNodeBootstrap() error = %v", err)
	}

	dest := filepath.Join(dir, "sentinelgate-hook.js")
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	// Check file mode (0644 on unix-like systems) — skip on Windows.
	if runtime.GOOS != "windows" {
		mode := info.Mode().Perm()
		if mode != 0644 {
			t.Errorf("file permissions = %o, want 0644", mode)
		}
	}
}

func TestPrepareBootstrapWritesNode(t *testing.T) {
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

	// Verify sentinelgate-hook.js exists in node dir.
	hookPath := filepath.Join(env.NodeDir, "sentinelgate-hook.js")
	info, err := os.Stat(hookPath)
	if err != nil {
		t.Fatalf("sentinelgate-hook.js not found in bootstrap: %v", err)
	}

	if info.Size() == 0 {
		t.Error("sentinelgate-hook.js in bootstrap is empty")
	}

	// Verify content contains SENTINELGATE_SERVER_ADDR.
	data, err := os.ReadFile(hookPath)
	if err != nil {
		t.Fatalf("read sentinelgate-hook.js: %v", err)
	}

	if !strings.Contains(string(data), "SENTINELGATE_SERVER_ADDR") {
		t.Error("sentinelgate-hook.js does not contain SENTINELGATE_SERVER_ADDR")
	}

	// Verify content contains key interception patterns.
	content := string(data)
	if !strings.Contains(content, "child_process") {
		t.Error("sentinelgate-hook.js does not contain child_process interception")
	}
	if !strings.Contains(content, "_sgEvaluateSync") {
		t.Error("sentinelgate-hook.js does not contain synchronous evaluation")
	}
}
