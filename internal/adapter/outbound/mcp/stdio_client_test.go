package mcp

import (
	"context"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Construction tests
// ---------------------------------------------------------------------------

func TestNewStdioClient(t *testing.T) {
	c := NewStdioClient("/usr/bin/echo", "hello", "world")

	if c.serverPath != "/usr/bin/echo" {
		t.Errorf("expected serverPath=/usr/bin/echo, got %q", c.serverPath)
	}
	if len(c.serverArgs) != 2 || c.serverArgs[0] != "hello" || c.serverArgs[1] != "world" {
		t.Errorf("expected serverArgs=[hello world], got %v", c.serverArgs)
	}
	if c.cmd != nil {
		t.Error("cmd should be nil before Start")
	}
}

func TestNewStdioClient_NoArgs(t *testing.T) {
	c := NewStdioClient("/usr/bin/true")

	if c.serverPath != "/usr/bin/true" {
		t.Errorf("expected serverPath=/usr/bin/true, got %q", c.serverPath)
	}
	if len(c.serverArgs) != 0 {
		t.Errorf("expected empty serverArgs, got %v", c.serverArgs)
	}
}

// ---------------------------------------------------------------------------
// SetEnv tests
// ---------------------------------------------------------------------------

func TestStdioClient_SetEnv(t *testing.T) {
	c := NewStdioClient("/usr/bin/env")
	env := map[string]string{"FOO": "bar", "BAZ": "qux"}
	c.SetEnv(env)

	if c.serverEnv == nil {
		t.Fatal("serverEnv should not be nil after SetEnv")
	}
	if c.serverEnv["FOO"] != "bar" {
		t.Errorf("expected FOO=bar, got %q", c.serverEnv["FOO"])
	}
	if c.serverEnv["BAZ"] != "qux" {
		t.Errorf("expected BAZ=qux, got %q", c.serverEnv["BAZ"])
	}
}

func TestStdioClient_SetEnv_Nil(t *testing.T) {
	c := NewStdioClient("/usr/bin/env")
	c.SetEnv(nil)

	if c.serverEnv != nil {
		t.Errorf("expected nil serverEnv, got %v", c.serverEnv)
	}
}

// ---------------------------------------------------------------------------
// Start error handling
// ---------------------------------------------------------------------------

func TestStdioClient_Start_InvalidCommand(t *testing.T) {
	c := NewStdioClient("/nonexistent/binary/that/does/not/exist")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _, err := c.Start(ctx)
	if err == nil {
		t.Fatal("expected error for nonexistent binary, got nil")
	}
	if !strings.Contains(err.Error(), "failed to start server") {
		t.Errorf("expected 'failed to start server' in error, got: %v", err)
	}

	// cmd should be nil after failed start.
	if c.cmd != nil {
		t.Error("cmd should be nil after failed Start")
	}
}

func TestStdioClient_Start_DoubleStartBlocked(t *testing.T) {
	// Use "cat" which reads stdin and keeps running.
	c := NewStdioClient("/bin/cat")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _, err := c.Start(ctx)
	if err != nil {
		t.Fatalf("first Start failed: %v", err)
	}
	defer func() { _ = c.Close() }()

	// Second Start should fail because cmd is already set.
	_, _, err = c.Start(ctx)
	if err == nil {
		t.Fatal("expected error on double Start, got nil")
	}
	if !strings.Contains(err.Error(), "already started") {
		t.Errorf("expected 'already started' error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Wait without Start
// ---------------------------------------------------------------------------

func TestStdioClient_Wait_NotStarted(t *testing.T) {
	c := NewStdioClient("/bin/echo")

	err := c.Wait()
	if err == nil {
		t.Fatal("expected error when calling Wait without Start")
	}
	if !strings.Contains(err.Error(), "not started") {
		t.Errorf("expected 'not started' error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Close behavior
// ---------------------------------------------------------------------------

func TestStdioClient_Close_NotStarted(t *testing.T) {
	c := NewStdioClient("/bin/echo")

	// Close on an un-started client should not error.
	err := c.Close()
	if err != nil {
		t.Errorf("Close on un-started client should not error, got: %v", err)
	}
}

func TestStdioClient_Close_AfterStart(t *testing.T) {
	c := NewStdioClient("/bin/cat")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _, err := c.Start(ctx)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	err = c.Close()
	if err != nil {
		t.Errorf("Close after Start should succeed, got: %v", err)
	}

	// After Close, cmd should be nil.
	if c.cmd != nil {
		t.Error("cmd should be nil after Close")
	}
}

func TestStdioClient_DoubleClose(t *testing.T) {
	c := NewStdioClient("/bin/cat")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _, err := c.Start(ctx)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	err = c.Close()
	if err != nil {
		t.Errorf("first Close failed: %v", err)
	}

	// Second Close should be safe (idempotent).
	err = c.Close()
	if err != nil {
		t.Errorf("second Close should not error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Start + communicate + Close lifecycle
// ---------------------------------------------------------------------------

func TestStdioClient_StartAndCommunicate(t *testing.T) {
	// "echo" writes its args to stdout and exits.
	c := NewStdioClient("/bin/echo", "test-output")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, stdout, err := c.Start(ctx)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	buf := make([]byte, 256)
	n, err := stdout.Read(buf)
	if err != nil {
		t.Fatalf("Read from stdout failed: %v", err)
	}

	output := strings.TrimSpace(string(buf[:n]))
	if output != "test-output" {
		t.Errorf("expected 'test-output', got %q", output)
	}

	// Wait for process to exit.
	if err := c.Wait(); err != nil {
		t.Errorf("Wait failed: %v", err)
	}

	_ = c.Close()
}

// ---------------------------------------------------------------------------
// Sensitive env filtering tests
// ---------------------------------------------------------------------------

func TestIsSensitiveKey_ExplicitBlock(t *testing.T) {
	cases := []struct {
		key      string
		expected bool
	}{
		{"AWS_SECRET_ACCESS_KEY", true},
		{"AWS_ACCESS_KEY_ID", true},
		{"GITHUB_TOKEN", true},
		{"OPENAI_API_KEY", true},
		{"DATABASE_URL", true},
		{"HOME", false},
		{"PATH", false},
		{"LANG", false},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			if got := isSensitiveKey(tc.key); got != tc.expected {
				t.Errorf("isSensitiveKey(%q) = %v, want %v", tc.key, got, tc.expected)
			}
		})
	}
}

func TestIsSensitiveKey_HeuristicPatterns(t *testing.T) {
	cases := []struct {
		key      string
		expected bool
	}{
		{"MY_SECRET_VALUE", true},
		{"DB_TOKEN_V2", true},
		{"CUSTOM_PASSWORD", true},
		{"MY_CREDENTIAL_FILE", true},
		{"MY_PRIVATE_KEY_PATH", true},
		{"SOME_API_KEY_EXTRA", true},
		{"NORMAL_CONFIG", false},
		{"APP_PORT", false},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			if got := isSensitiveKey(tc.key); got != tc.expected {
				t.Errorf("isSensitiveKey(%q) = %v, want %v", tc.key, got, tc.expected)
			}
		})
	}
}

func TestSanitizedEnviron_ExcludesSensitive(t *testing.T) {
	// Set a known sensitive and a non-sensitive var.
	t.Setenv("TEST_SANITIZE_SECRET_VALUE", "hidden")
	t.Setenv("TEST_SANITIZE_NORMAL", "visible")

	env := sanitizedEnviron()

	foundSecret := false
	foundNormal := false
	for _, e := range env {
		if strings.HasPrefix(e, "TEST_SANITIZE_SECRET_VALUE=") {
			foundSecret = true
		}
		if strings.HasPrefix(e, "TEST_SANITIZE_NORMAL=") {
			foundNormal = true
		}
	}

	if foundSecret {
		t.Error("sensitive key TEST_SANITIZE_SECRET_VALUE should have been filtered")
	}
	if !foundNormal {
		t.Error("non-sensitive key TEST_SANITIZE_NORMAL should be present")
	}
}
