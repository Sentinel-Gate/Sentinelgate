package service

import (
	"sync"
	"testing"
	"time"
)

func TestAgentRegistry_RegisterAndList(t *testing.T) {
	r := NewAgentRegistry()

	info := AgentInfo{
		ID:        "agent-1",
		Command:   "python",
		Args:      []string{"agent.py"},
		Framework: "langchain",
		FailMode:  "open",
		StartedAt: time.Now().UTC(),
		Status:    "running",
		PID:       1234,
	}

	r.Register(info)

	agents := r.List()
	if len(agents) != 1 {
		t.Fatalf("List() returned %d agents, want 1", len(agents))
	}
	if agents[0].ID != "agent-1" {
		t.Errorf("ID = %q, want %q", agents[0].ID, "agent-1")
	}
	if agents[0].Command != "python" {
		t.Errorf("Command = %q, want %q", agents[0].Command, "python")
	}
	if agents[0].Status != "running" {
		t.Errorf("Status = %q, want %q", agents[0].Status, "running")
	}
}

func TestAgentRegistry_Get(t *testing.T) {
	r := NewAgentRegistry()

	info := AgentInfo{
		ID:      "agent-1",
		Command: "node",
		Status:  "running",
	}
	r.Register(info)

	got, ok := r.Get("agent-1")
	if !ok {
		t.Fatal("Get(agent-1) returned false, want true")
	}
	if got.Command != "node" {
		t.Errorf("Command = %q, want %q", got.Command, "node")
	}

	_, ok = r.Get("nonexistent")
	if ok {
		t.Error("Get(nonexistent) returned true, want false")
	}
}

func TestAgentRegistry_Unregister(t *testing.T) {
	r := NewAgentRegistry()

	r.Register(AgentInfo{ID: "agent-1", Command: "python", Status: "running"})
	r.Register(AgentInfo{ID: "agent-2", Command: "node", Status: "running"})

	r.Unregister("agent-1")

	agents := r.List()
	if len(agents) != 1 {
		t.Fatalf("List() returned %d agents after Unregister, want 1", len(agents))
	}
	if agents[0].ID != "agent-2" {
		t.Errorf("remaining agent ID = %q, want %q", agents[0].ID, "agent-2")
	}

	_, ok := r.Get("agent-1")
	if ok {
		t.Error("Get(agent-1) returned true after Unregister, want false")
	}
}

func TestAgentRegistry_SetStatus(t *testing.T) {
	r := NewAgentRegistry()

	r.Register(AgentInfo{ID: "agent-1", Command: "python", Status: "running"})
	r.SetStatus("agent-1", "stopped")

	got, ok := r.Get("agent-1")
	if !ok {
		t.Fatal("Get(agent-1) returned false")
	}
	if got.Status != "stopped" {
		t.Errorf("Status = %q, want %q", got.Status, "stopped")
	}

	// SetStatus on nonexistent agent should not panic
	r.SetStatus("nonexistent", "stopped")
}

func TestAgentRegistry_ListSortedByStartedAtDescending(t *testing.T) {
	r := NewAgentRegistry()

	now := time.Now().UTC()
	r.Register(AgentInfo{ID: "oldest", StartedAt: now.Add(-2 * time.Hour), Status: "running"})
	r.Register(AgentInfo{ID: "newest", StartedAt: now, Status: "running"})
	r.Register(AgentInfo{ID: "middle", StartedAt: now.Add(-1 * time.Hour), Status: "running"})

	agents := r.List()
	if len(agents) != 3 {
		t.Fatalf("List() returned %d agents, want 3", len(agents))
	}
	if agents[0].ID != "newest" {
		t.Errorf("agents[0].ID = %q, want %q", agents[0].ID, "newest")
	}
	if agents[1].ID != "middle" {
		t.Errorf("agents[1].ID = %q, want %q", agents[1].ID, "middle")
	}
	if agents[2].ID != "oldest" {
		t.Errorf("agents[2].ID = %q, want %q", agents[2].ID, "oldest")
	}
}

func TestAgentRegistry_ConcurrentAccess(t *testing.T) {
	r := NewAgentRegistry()
	var wg sync.WaitGroup

	// Concurrent Register
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			r.Register(AgentInfo{
				ID:        "agent-" + string(rune('a'+idx%26)),
				Command:   "python",
				StartedAt: time.Now().UTC(),
				Status:    "running",
			})
		}(i)
	}

	// Concurrent List
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = r.List()
		}()
	}

	// Concurrent Get
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			r.Get("agent-" + string(rune('a'+idx%26)))
		}(i)
	}

	// Concurrent SetStatus
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			r.SetStatus("agent-"+string(rune('a'+idx%26)), "stopped")
		}(i)
	}

	wg.Wait()

	// Verify no panics occurred and List still works
	agents := r.List()
	if len(agents) == 0 {
		t.Error("List() returned 0 agents after concurrent writes, expected some")
	}
}
