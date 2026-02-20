// Package service provides business logic services for SentinelGate.
package service

import (
	"sort"
	"sync"
	"time"
)

// AgentInfo represents a running agent process tracked by SentinelGate.
type AgentInfo struct {
	ID        string    `json:"id"`
	Command   string    `json:"command"`
	Args      []string  `json:"args"`
	Framework string    `json:"framework,omitempty"`
	FailMode  string    `json:"fail_mode"`
	StartedAt time.Time `json:"started_at"`
	Status    string    `json:"status"` // "running", "stopped"
	PID       int       `json:"pid,omitempty"`
}

// AgentRegistry tracks running agent processes in memory.
// It is safe for concurrent use.
type AgentRegistry struct {
	mu     sync.RWMutex
	agents map[string]*AgentInfo
}

// NewAgentRegistry creates a new empty AgentRegistry.
func NewAgentRegistry() *AgentRegistry {
	return &AgentRegistry{
		agents: make(map[string]*AgentInfo),
	}
}

// Register adds or updates an agent in the registry.
func (r *AgentRegistry) Register(info AgentInfo) {
	r.mu.Lock()
	defer r.mu.Unlock()
	copied := info
	r.agents[info.ID] = &copied
}

// Unregister removes an agent from the registry.
func (r *AgentRegistry) Unregister(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.agents, id)
}

// List returns all agents sorted by StartedAt descending (newest first).
func (r *AgentRegistry) List() []AgentInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]AgentInfo, 0, len(r.agents))
	for _, a := range r.agents {
		result = append(result, *a)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].StartedAt.After(result[j].StartedAt)
	})

	return result
}

// Get returns a single agent by ID. Returns nil, false if not found.
func (r *AgentRegistry) Get(id string) (*AgentInfo, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.agents[id]
	if !ok {
		return nil, false
	}
	copied := *a
	return &copied, true
}

// SetStatus updates the status of an agent by ID.
// Does nothing if the agent is not found.
func (r *AgentRegistry) SetStatus(id, status string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a, ok := r.agents[id]; ok {
		a.Status = status
	}
}
