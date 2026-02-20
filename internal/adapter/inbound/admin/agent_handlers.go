package admin

import (
	"net/http"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/service"
)

// WithAgentRegistry sets the agent registry on the AdminAPIHandler.
func WithAgentRegistry(r *service.AgentRegistry) AdminAPIOption {
	return func(h *AdminAPIHandler) { h.agentRegistry = r }
}

// envVarEntry describes an environment variable for agent manual setup.
type envVarEntry struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	Description string `json:"description"`
}

// envVarsResponse wraps the list of environment variables.
type envVarsResponse struct {
	EnvVars []envVarEntry `json:"env_vars"`
}

// handleListAgents returns the list of running agents from the registry.
// GET /admin/api/agents
func (h *AdminAPIHandler) handleListAgents(w http.ResponseWriter, r *http.Request) {
	if h.agentRegistry == nil {
		h.respondJSON(w, http.StatusOK, []service.AgentInfo{})
		return
	}
	agents := h.agentRegistry.List()
	h.respondJSON(w, http.StatusOK, agents)
}

// registerAgentRequest is the JSON body for agent registration.
type registerAgentRequest struct {
	ID        string   `json:"id"`
	Command   string   `json:"command"`
	Args      []string `json:"args"`
	Framework string   `json:"framework,omitempty"`
	FailMode  string   `json:"fail_mode"`
	PID       int      `json:"pid,omitempty"`
}

// handleRegisterAgent registers a running agent in the registry.
// POST /admin/api/agents/register
func (h *AdminAPIHandler) handleRegisterAgent(w http.ResponseWriter, r *http.Request) {
	if h.agentRegistry == nil {
		h.respondError(w, http.StatusServiceUnavailable, "agent registry not available")
		return
	}

	var req registerAgentRequest
	if err := h.readJSON(r, &req); err != nil {
		h.respondError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.ID == "" {
		h.respondError(w, http.StatusBadRequest, "id is required")
		return
	}
	if req.Command == "" {
		h.respondError(w, http.StatusBadRequest, "command is required")
		return
	}

	info := service.AgentInfo{
		ID:        req.ID,
		Command:   req.Command,
		Args:      req.Args,
		Framework: req.Framework,
		FailMode:  req.FailMode,
		StartedAt: time.Now().UTC(),
		Status:    "running",
		PID:       req.PID,
	}
	h.agentRegistry.Register(info)

	h.respondJSON(w, http.StatusCreated, info)
}

// handleUnregisterAgent removes an agent from the registry.
// DELETE /admin/api/agents/{id}
func (h *AdminAPIHandler) handleUnregisterAgent(w http.ResponseWriter, r *http.Request) {
	if h.agentRegistry == nil {
		h.respondError(w, http.StatusServiceUnavailable, "agent registry not available")
		return
	}

	id := h.pathParam(r, "id")
	if id == "" {
		h.respondError(w, http.StatusBadRequest, "agent id is required")
		return
	}

	h.agentRegistry.Unregister(id)
	w.WriteHeader(http.StatusNoContent)
}

// handleGetAgentEnv returns the environment variables needed for manual agent setup.
// GET /admin/api/agents/env
func (h *AdminAPIHandler) handleGetAgentEnv(w http.ResponseWriter, _ *http.Request) {
	resp := envVarsResponse{
		EnvVars: []envVarEntry{
			{
				Name:        "SENTINELGATE_SERVER_ADDR",
				Value:       "http://localhost:8080",
				Description: "SentinelGate server address",
			},
			{
				Name:        "SENTINELGATE_API_KEY",
				Value:       "<generated on key creation>",
				Description: "API key for authentication",
			},
			{
				Name:        "SENTINELGATE_FAIL_MODE",
				Value:       "open",
				Description: "Behavior when server unreachable: open or closed",
			},
			{
				Name:        "SENTINELGATE_CACHE_TTL",
				Value:       "5s",
				Description: "LRU cache TTL for recently-allowed patterns",
			},
		},
	}
	h.respondJSON(w, http.StatusOK, resp)
}
