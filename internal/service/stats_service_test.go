package service

import (
	"sync"
	"testing"
)

func TestStatsService_RecordAndGet(t *testing.T) {
	s := NewStatsService()

	s.RecordAllow()
	s.RecordAllow()
	s.RecordDeny()
	s.RecordRateLimited()
	s.RecordError()
	s.RecordError()
	s.RecordError()

	stats := s.GetStats()

	if stats.Allowed != 2 {
		t.Errorf("Allowed = %d, want 2", stats.Allowed)
	}
	if stats.Denied != 1 {
		t.Errorf("Denied = %d, want 1", stats.Denied)
	}
	if stats.RateLimited != 1 {
		t.Errorf("RateLimited = %d, want 1", stats.RateLimited)
	}
	if stats.Errors != 3 {
		t.Errorf("Errors = %d, want 3", stats.Errors)
	}
}

func TestStatsService_Reset(t *testing.T) {
	s := NewStatsService()

	s.RecordAllow()
	s.RecordDeny()
	s.RecordRateLimited()
	s.RecordError()

	s.Reset()

	stats := s.GetStats()
	if stats.Allowed != 0 || stats.Denied != 0 || stats.RateLimited != 0 || stats.Errors != 0 {
		t.Errorf("after Reset, stats should be all zero: got %+v", stats)
	}
}

func TestStatsService_ConcurrentAccess(t *testing.T) {
	s := NewStatsService()

	const goroutines = 100
	const opsPerGoroutine = 1000

	var wg sync.WaitGroup
	wg.Add(goroutines * 4)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				s.RecordAllow()
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				s.RecordDeny()
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				s.RecordRateLimited()
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				s.RecordError()
			}
		}()
	}

	wg.Wait()

	stats := s.GetStats()
	expected := int64(goroutines * opsPerGoroutine)

	if stats.Allowed != expected {
		t.Errorf("Allowed = %d, want %d", stats.Allowed, expected)
	}
	if stats.Denied != expected {
		t.Errorf("Denied = %d, want %d", stats.Denied, expected)
	}
	if stats.RateLimited != expected {
		t.Errorf("RateLimited = %d, want %d", stats.RateLimited, expected)
	}
	if stats.Errors != expected {
		t.Errorf("Errors = %d, want %d", stats.Errors, expected)
	}
}

func TestStatsService_InitialZero(t *testing.T) {
	s := NewStatsService()
	stats := s.GetStats()

	if stats.Allowed != 0 || stats.Denied != 0 || stats.RateLimited != 0 || stats.Errors != 0 {
		t.Errorf("new StatsService should have all zero counters: got %+v", stats)
	}
	if len(stats.ProtocolCounts) != 0 {
		t.Errorf("new StatsService should have empty protocol counts, got %+v", stats.ProtocolCounts)
	}
	if len(stats.FrameworkCounts) != 0 {
		t.Errorf("new StatsService should have empty framework counts, got %+v", stats.FrameworkCounts)
	}
}

func TestStatsService_RecordProtocol(t *testing.T) {
	s := NewStatsService()

	s.RecordProtocol("mcp")
	s.RecordProtocol("mcp")
	s.RecordProtocol("http")
	s.RecordProtocol("websocket")
	s.RecordProtocol("http")
	s.RecordProtocol("http")

	stats := s.GetStats()
	if stats.ProtocolCounts["mcp"] != 2 {
		t.Errorf("mcp = %d, want 2", stats.ProtocolCounts["mcp"])
	}
	if stats.ProtocolCounts["http"] != 3 {
		t.Errorf("http = %d, want 3", stats.ProtocolCounts["http"])
	}
	if stats.ProtocolCounts["websocket"] != 1 {
		t.Errorf("websocket = %d, want 1", stats.ProtocolCounts["websocket"])
	}
	if stats.ProtocolCounts["runtime"] != 0 {
		t.Errorf("runtime = %d, want 0", stats.ProtocolCounts["runtime"])
	}
}

func TestStatsService_RecordProtocol_SkipsEmpty(t *testing.T) {
	s := NewStatsService()

	s.RecordProtocol("")
	s.RecordProtocol("mcp")

	stats := s.GetStats()
	if len(stats.ProtocolCounts) != 1 {
		t.Errorf("expected 1 protocol entry, got %d: %+v", len(stats.ProtocolCounts), stats.ProtocolCounts)
	}
}

func TestStatsService_RecordFramework(t *testing.T) {
	s := NewStatsService()

	s.RecordFramework("langchain")
	s.RecordFramework("langchain")
	s.RecordFramework("crewai")
	s.RecordFramework("autogen")
	s.RecordFramework("langchain")

	stats := s.GetStats()
	if stats.FrameworkCounts["langchain"] != 3 {
		t.Errorf("langchain = %d, want 3", stats.FrameworkCounts["langchain"])
	}
	if stats.FrameworkCounts["crewai"] != 1 {
		t.Errorf("crewai = %d, want 1", stats.FrameworkCounts["crewai"])
	}
	if stats.FrameworkCounts["autogen"] != 1 {
		t.Errorf("autogen = %d, want 1", stats.FrameworkCounts["autogen"])
	}
}

func TestStatsService_RecordFramework_SkipsEmpty(t *testing.T) {
	s := NewStatsService()

	s.RecordFramework("")
	s.RecordFramework("")
	s.RecordFramework("langchain")

	stats := s.GetStats()
	if len(stats.FrameworkCounts) != 1 {
		t.Errorf("expected 1 framework entry, got %d: %+v", len(stats.FrameworkCounts), stats.FrameworkCounts)
	}
}

func TestStatsService_GetStats_ProtocolFrameworkSnapshot(t *testing.T) {
	s := NewStatsService()

	s.RecordProtocol("mcp")
	s.RecordProtocol("http")
	s.RecordFramework("langchain")

	stats := s.GetStats()

	// Verify it's a copy (modifying returned map shouldn't affect service)
	stats.ProtocolCounts["mcp"] = 999
	stats.FrameworkCounts["langchain"] = 999

	stats2 := s.GetStats()
	if stats2.ProtocolCounts["mcp"] != 1 {
		t.Errorf("snapshot should be a copy, got mcp = %d", stats2.ProtocolCounts["mcp"])
	}
	if stats2.FrameworkCounts["langchain"] != 1 {
		t.Errorf("snapshot should be a copy, got langchain = %d", stats2.FrameworkCounts["langchain"])
	}
}

func TestStatsService_Reset_ClearsProtocolFramework(t *testing.T) {
	s := NewStatsService()

	s.RecordProtocol("mcp")
	s.RecordProtocol("http")
	s.RecordFramework("langchain")
	s.RecordFramework("crewai")

	s.Reset()

	stats := s.GetStats()
	if len(stats.ProtocolCounts) != 0 {
		t.Errorf("after Reset, protocol counts should be empty: got %+v", stats.ProtocolCounts)
	}
	if len(stats.FrameworkCounts) != 0 {
		t.Errorf("after Reset, framework counts should be empty: got %+v", stats.FrameworkCounts)
	}
}

func TestStatsService_ConcurrentProtocolFramework(t *testing.T) {
	s := NewStatsService()

	const goroutines = 50
	const opsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				s.RecordProtocol("mcp")
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				s.RecordFramework("langchain")
			}
		}()
	}

	wg.Wait()

	stats := s.GetStats()
	expected := int64(goroutines * opsPerGoroutine)
	if stats.ProtocolCounts["mcp"] != expected {
		t.Errorf("mcp = %d, want %d", stats.ProtocolCounts["mcp"], expected)
	}
	if stats.FrameworkCounts["langchain"] != expected {
		t.Errorf("langchain = %d, want %d", stats.FrameworkCounts["langchain"], expected)
	}
}
