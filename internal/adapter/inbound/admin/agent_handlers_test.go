package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

func testAgentEnv(t *testing.T, registry *service.AgentRegistry) *AdminAPIHandler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	opts := []AdminAPIOption{
		WithAPILogger(logger),
	}
	if registry != nil {
		opts = append(opts, WithAgentRegistry(registry))
	}
	return NewAdminAPIHandler(opts...)
}

func TestHandleListAgents_EmptyRegistry(t *testing.T) {
	registry := service.NewAgentRegistry()
	h := testAgentEnv(t, registry)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/agents", nil)
	w := httptest.NewRecorder()

	h.handleListAgents(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var agents []service.AgentInfo
	if err := json.NewDecoder(resp.Body).Decode(&agents); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(agents) != 0 {
		t.Errorf("agents count = %d, want 0", len(agents))
	}
}

func TestHandleListAgents_WithRegisteredAgents(t *testing.T) {
	registry := service.NewAgentRegistry()
	registry.Register(service.AgentInfo{
		ID:        "agent-abc",
		Command:   "python",
		Args:      []string{"agent.py"},
		Framework: "langchain",
		FailMode:  "open",
		StartedAt: time.Now().UTC(),
		Status:    "running",
		PID:       1234,
	})
	registry.Register(service.AgentInfo{
		ID:        "agent-def",
		Command:   "node",
		Args:      []string{"agent.js"},
		FailMode:  "closed",
		StartedAt: time.Now().UTC().Add(-time.Minute),
		Status:    "running",
		PID:       5678,
	})

	h := testAgentEnv(t, registry)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/agents", nil)
	w := httptest.NewRecorder()

	h.handleListAgents(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var agents []service.AgentInfo
	if err := json.NewDecoder(resp.Body).Decode(&agents); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(agents) != 2 {
		t.Fatalf("agents count = %d, want 2", len(agents))
	}

	// Newest first
	if agents[0].ID != "agent-abc" {
		t.Errorf("agents[0].ID = %q, want %q", agents[0].ID, "agent-abc")
	}
}

func TestHandleListAgents_NilRegistry(t *testing.T) {
	h := testAgentEnv(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/agents", nil)
	w := httptest.NewRecorder()

	h.handleListAgents(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var agents []service.AgentInfo
	if err := json.NewDecoder(resp.Body).Decode(&agents); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(agents) != 0 {
		t.Errorf("agents count = %d, want 0 (nil registry)", len(agents))
	}
}

func TestHandleGetAgentEnv_ReturnsExpectedVars(t *testing.T) {
	h := testAgentEnv(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/agents/env", nil)
	w := httptest.NewRecorder()

	h.handleGetAgentEnv(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var body envVarsResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if len(body.EnvVars) != 4 {
		t.Fatalf("env_vars count = %d, want 4", len(body.EnvVars))
	}

	expectedNames := []string{
		"SENTINELGATE_SERVER_ADDR",
		"SENTINELGATE_API_KEY",
		"SENTINELGATE_FAIL_MODE",
		"SENTINELGATE_CACHE_TTL",
	}
	for i, name := range expectedNames {
		if body.EnvVars[i].Name != name {
			t.Errorf("env_vars[%d].Name = %q, want %q", i, body.EnvVars[i].Name, name)
		}
		if body.EnvVars[i].Description == "" {
			t.Errorf("env_vars[%d].Description is empty", i)
		}
	}
}
