package runtime

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWritePythonBootstrap_CreatesFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	if err := WritePythonBootstrap(dir); err != nil {
		t.Fatalf("WritePythonBootstrap() error = %v", err)
	}

	dest := filepath.Join(dir, "sitecustomize.py")
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("sitecustomize.py not found: %v", err)
	}
	if info.Size() == 0 {
		t.Error("sitecustomize.py is empty")
	}

	// Verify file permissions are 0644 — skip on Windows where Unix permissions are unsupported.
	if runtime.GOOS != "windows" {
		perm := info.Mode().Perm()
		if perm != 0644 {
			t.Errorf("file permissions = %o, want 0644", perm)
		}
	}
}

func TestWritePythonBootstrap_ContentValid(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	if err := WritePythonBootstrap(dir); err != nil {
		t.Fatalf("WritePythonBootstrap() error = %v", err)
	}

	content, err := os.ReadFile(filepath.Join(dir, "sitecustomize.py"))
	if err != nil {
		t.Fatalf("ReadFile error = %v", err)
	}

	s := string(content)

	// The embedded file must contain key markers.
	markers := []string{
		"SENTINELGATE_SERVER_ADDR",
		"_SentinelGateClient",
		"subprocess",
		"builtins.open",
		"/admin/api/v1/policy/evaluate",
		"_poll_approval",
		"OrderedDict",
		"threading.Lock",
	}
	for _, m := range markers {
		if !strings.Contains(s, m) {
			t.Errorf("sitecustomize.py missing expected content: %q", m)
		}
	}
}

func TestEmbeddedPythonSitecustomize_NonEmpty(t *testing.T) {
	t.Parallel()

	if len(pythonSitecustomize) == 0 {
		t.Fatal("pythonSitecustomize embedded content is empty")
	}

	s := string(pythonSitecustomize)
	if !strings.Contains(s, "SENTINELGATE_SERVER_ADDR") {
		t.Error("embedded content does not contain SENTINELGATE_SERVER_ADDR")
	}
}

func TestPrepareBootstrapWritesPython(t *testing.T) {
	t.Parallel()

	cfg := BootstrapConfig{
		ServerAddr: "http://localhost:8080",
		APIKey:     "sg_runtime_test_python",
		AgentID:    "test-agent-python-id",
	}

	env, err := PrepareBootstrap(cfg)
	if err != nil {
		t.Fatalf("PrepareBootstrap() error = %v", err)
	}
	defer Cleanup(env)

	// Verify sitecustomize.py exists in the python directory.
	scPath := filepath.Join(env.PythonDir, "sitecustomize.py")
	info, err := os.Stat(scPath)
	if err != nil {
		t.Fatalf("sitecustomize.py not found in bootstrap python dir: %v", err)
	}
	if info.Size() == 0 {
		t.Error("sitecustomize.py is empty")
	}

	// Read content and verify key markers.
	content, err := os.ReadFile(scPath)
	if err != nil {
		t.Fatalf("ReadFile error = %v", err)
	}

	s := string(content)
	if !strings.Contains(s, "SENTINELGATE_SERVER_ADDR") {
		t.Error("sitecustomize.py missing SENTINELGATE_SERVER_ADDR")
	}
	if !strings.Contains(s, "_SentinelGateClient") {
		t.Error("sitecustomize.py missing _SentinelGateClient class")
	}
	if !strings.Contains(s, "/admin/api/v1/policy/evaluate") {
		t.Error("sitecustomize.py missing policy evaluate endpoint")
	}
}
