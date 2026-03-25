package upstream

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"
)

// helper to build a DiscoveredTool with minimal boilerplate.
func makeTool(name, upstreamID string) *DiscoveredTool {
	return &DiscoveredTool{
		Name:         name,
		Description:  name + " description",
		InputSchema:  json.RawMessage(`{"type":"object"}`),
		UpstreamID:   upstreamID,
		UpstreamName: "upstream-" + upstreamID,
		DiscoveredAt: time.Now(),
	}
}

func TestToolCacheGetTool(t *testing.T) {
	cache := NewToolCache()

	tools := []*DiscoveredTool{
		makeTool("read_file", "u1"),
		makeTool("write_file", "u1"),
	}
	cache.SetToolsForUpstream("u1", tools)

	// Lookup existing tool.
	got, ok := cache.GetTool("read_file")
	if !ok {
		t.Fatal("expected to find read_file")
	}
	if got.Name != "read_file" {
		t.Errorf("name = %q, want %q", got.Name, "read_file")
	}
	if got.UpstreamID != "u1" {
		t.Errorf("upstreamID = %q, want %q", got.UpstreamID, "u1")
	}

	// Lookup missing tool.
	_, ok = cache.GetTool("nonexistent")
	if ok {
		t.Error("expected nonexistent tool lookup to return false")
	}
}

func TestToolCacheGetAllTools(t *testing.T) {
	cache := NewToolCache()

	cache.SetToolsForUpstream("u1", []*DiscoveredTool{
		makeTool("tool_a", "u1"),
		makeTool("tool_b", "u1"),
	})
	cache.SetToolsForUpstream("u2", []*DiscoveredTool{
		makeTool("tool_c", "u2"),
	})

	all := cache.GetAllTools()
	if len(all) != 3 {
		t.Fatalf("GetAllTools length = %d, want 3", len(all))
	}

	names := make(map[string]bool)
	for _, tool := range all {
		names[tool.Name] = true
	}
	for _, want := range []string{"tool_a", "tool_b", "tool_c"} {
		if !names[want] {
			t.Errorf("missing tool %q in GetAllTools result", want)
		}
	}
}

func TestToolCachePopulate(t *testing.T) {
	cache := NewToolCache()

	tools := []*DiscoveredTool{
		makeTool("alpha", "u1"),
		makeTool("beta", "u1"),
	}
	cache.SetToolsForUpstream("u1", tools)

	// Verify by-upstream index.
	byUp := cache.GetToolsByUpstream("u1")
	if len(byUp) != 2 {
		t.Fatalf("GetToolsByUpstream length = %d, want 2", len(byUp))
	}

	// Verify Count.
	if cache.Count() != 2 {
		t.Errorf("Count = %d, want 2", cache.Count())
	}

	// Replace with a different set.
	cache.SetToolsForUpstream("u1", []*DiscoveredTool{
		makeTool("gamma", "u1"),
	})
	if cache.Count() != 1 {
		t.Errorf("after replace Count = %d, want 1", cache.Count())
	}
	_, ok := cache.GetTool("alpha")
	if ok {
		t.Error("old tool alpha should be gone after replace")
	}
	_, ok = cache.GetTool("gamma")
	if !ok {
		t.Error("new tool gamma should exist after replace")
	}
}

func TestToolCacheRemoveUpstream(t *testing.T) {
	cache := NewToolCache()

	cache.SetToolsForUpstream("u1", []*DiscoveredTool{
		makeTool("tool_x", "u1"),
	})
	cache.SetToolsForUpstream("u2", []*DiscoveredTool{
		makeTool("tool_y", "u2"),
	})

	cache.RemoveUpstream("u1")

	// u1 tools gone.
	_, ok := cache.GetTool("tool_x")
	if ok {
		t.Error("tool_x should be removed after RemoveUpstream")
	}
	byUp := cache.GetToolsByUpstream("u1")
	if byUp != nil {
		t.Error("GetToolsByUpstream should return nil for removed upstream")
	}

	// u2 tools untouched.
	_, ok = cache.GetTool("tool_y")
	if !ok {
		t.Error("tool_y from u2 should still exist")
	}
	if cache.Count() != 1 {
		t.Errorf("Count = %d, want 1", cache.Count())
	}
}

func TestToolCacheConcurrentAccess(t *testing.T) {
	cache := NewToolCache()

	var wg sync.WaitGroup
	const goroutines = 20

	// Writers: each goroutine sets tools for its own upstream.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			uid := fmt.Sprintf("u%d", id)
			cache.SetToolsForUpstream(uid, []*DiscoveredTool{
				makeTool(fmt.Sprintf("tool_%d", id), uid),
			})
		}(i)
	}

	// Readers: concurrently read while writers are active.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			cache.GetAllTools()
			cache.GetTool(fmt.Sprintf("tool_%d", id))
			cache.GetToolsByUpstream(fmt.Sprintf("u%d", id))
			cache.Count()
		}(i)
	}

	wg.Wait()

	// After all goroutines complete, every upstream should have its tool.
	if cache.Count() != goroutines {
		t.Errorf("Count = %d, want %d", cache.Count(), goroutines)
	}
}

func TestToolCacheNamespacing(t *testing.T) {
	cache := NewToolCache()

	// Two upstreams register a tool with the same name.
	cache.SetToolsForUpstream("u1", []*DiscoveredTool{
		makeTool("shared_tool", "u1"),
	})
	cache.SetToolsForUpstream("u2", []*DiscoveredTool{
		makeTool("shared_tool", "u2"),
	})

	// Both tools should be accessible via namespaced names.
	got1, ok1 := cache.GetTool("upstream-u1/shared_tool")
	if !ok1 {
		t.Fatal("expected upstream-u1/shared_tool to exist")
	}
	if got1.UpstreamID != "u1" {
		t.Errorf("upstream-u1/shared_tool upstream = %q, want %q", got1.UpstreamID, "u1")
	}

	got2, ok2 := cache.GetTool("upstream-u2/shared_tool")
	if !ok2 {
		t.Fatal("expected upstream-u2/shared_tool to exist")
	}
	if got2.UpstreamID != "u2" {
		t.Errorf("upstream-u2/shared_tool upstream = %q, want %q", got2.UpstreamID, "u2")
	}

	// Bare name should NOT be found (ambiguous).
	_, okBare := cache.GetTool("shared_tool")
	if okBare {
		t.Error("expected bare shared_tool to NOT be found (ambiguous)")
	}

	// IsAmbiguous should return true with suggestions.
	ambig, suggestions := cache.IsAmbiguous("shared_tool")
	if !ambig {
		t.Error("expected shared_tool to be ambiguous")
	}
	if len(suggestions) != 2 {
		t.Errorf("expected 2 suggestions, got %d", len(suggestions))
	}

	// GetAllTools should return both namespaced tools.
	all := cache.GetAllTools()
	if len(all) != 2 {
		t.Errorf("GetAllTools count = %d, want 2", len(all))
	}

	// Count should reflect resolved count.
	if cache.Count() != 2 {
		t.Errorf("Count = %d, want 2", cache.Count())
	}

	// A conflict should have been recorded.
	conflicts := cache.GetConflicts()
	if len(conflicts) == 0 {
		t.Fatal("expected at least one conflict to be recorded")
	}
	found := false
	for _, c := range conflicts {
		if c.ToolName == "shared_tool" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected a conflict entry for shared_tool")
	}

	// When one upstream is removed, namespace should be dropped.
	cache.RemoveUpstream("u2")
	got, ok := cache.GetTool("shared_tool")
	if !ok {
		t.Fatal("expected shared_tool to exist without namespace after removing u2")
	}
	if got.UpstreamID != "u1" {
		t.Errorf("shared_tool upstream = %q, want %q", got.UpstreamID, "u1")
	}

	// ClearConflicts should reset.
	cache.ClearConflicts()
	if c := cache.GetConflicts(); c != nil {
		t.Errorf("after ClearConflicts, got %d conflicts, want nil", len(c))
	}
}

// helper for tools with custom upstream name
func makeToolWithName(name, upstreamID, upstreamName string) *DiscoveredTool {
	return &DiscoveredTool{
		Name:         name,
		Description:  name + " description",
		InputSchema:  json.RawMessage(`{"type":"object"}`),
		UpstreamID:   upstreamID,
		UpstreamName: upstreamName,
		DiscoveredAt: time.Now(),
	}
}

func TestToolCache_NoNamespaceWhenUnique(t *testing.T) {
	cache := NewToolCache()

	cache.SetToolsForUpstream("u1", []*DiscoveredTool{
		makeTool("read_file", "u1"),
	})

	// Single upstream — no namespace prefix needed.
	all := cache.GetAllTools()
	if len(all) != 1 {
		t.Fatalf("GetAllTools length = %d, want 1", len(all))
	}
	if all[0].Name != "read_file" {
		t.Errorf("Name = %q, want %q", all[0].Name, "read_file")
	}

	got, ok := cache.GetTool("read_file")
	if !ok {
		t.Fatal("expected GetTool(read_file) to succeed")
	}
	if got.UpstreamID != "u1" {
		t.Errorf("UpstreamID = %q, want %q", got.UpstreamID, "u1")
	}
}

func TestToolCache_BareNameAmbiguous(t *testing.T) {
	cache := NewToolCache()

	cache.SetToolsForUpstream("u1", []*DiscoveredTool{
		makeTool("read_file", "u1"),
	})
	cache.SetToolsForUpstream("u2", []*DiscoveredTool{
		makeTool("read_file", "u2"),
	})

	// Bare name should be ambiguous — not found.
	_, ok := cache.GetTool("read_file")
	if ok {
		t.Error("expected bare read_file to NOT be found (ambiguous)")
	}

	ambig, suggestions := cache.IsAmbiguous("read_file")
	if !ambig {
		t.Fatal("expected read_file to be ambiguous")
	}
	if len(suggestions) != 2 {
		t.Errorf("expected 2 suggestions, got %d: %v", len(suggestions), suggestions)
	}
}

func TestToolCache_NamespaceRemovedWhenConflictResolved(t *testing.T) {
	cache := NewToolCache()

	cache.SetToolsForUpstream("u1", []*DiscoveredTool{
		makeTool("read_file", "u1"),
	})
	cache.SetToolsForUpstream("u2", []*DiscoveredTool{
		makeTool("read_file", "u2"),
	})

	// Confirm namespace is active.
	_, okBare := cache.GetTool("read_file")
	if okBare {
		t.Fatal("expected bare read_file to be ambiguous before removal")
	}
	_, okNs := cache.GetTool("upstream-u1/read_file")
	if !okNs {
		t.Fatal("expected upstream-u1/read_file to exist")
	}

	// Remove u2 — conflict resolved, namespace should drop.
	cache.RemoveUpstream("u2")

	got, ok := cache.GetTool("read_file")
	if !ok {
		t.Fatal("expected read_file to be accessible without namespace after removing u2")
	}
	if got.UpstreamID != "u1" {
		t.Errorf("UpstreamID = %q, want %q", got.UpstreamID, "u1")
	}

	// Namespaced form should no longer resolve.
	_, okOldNs := cache.GetTool("upstream-u1/read_file")
	if okOldNs {
		t.Error("expected upstream-u1/read_file to NOT exist after conflict resolved")
	}
}

func TestToolCache_MixedNamespaceAndUnique(t *testing.T) {
	cache := NewToolCache()

	cache.SetToolsForUpstream("u1", []*DiscoveredTool{
		makeToolWithName("read_file", "u1", "desktop"),
		makeToolWithName("custom_tool", "u1", "desktop"),
	})
	cache.SetToolsForUpstream("u2", []*DiscoveredTool{
		makeToolWithName("read_file", "u2", "train"),
		makeToolWithName("other_tool", "u2", "train"),
	})

	all := cache.GetAllTools()
	if len(all) != 4 {
		t.Fatalf("GetAllTools length = %d, want 4", len(all))
	}

	names := make(map[string]bool)
	for _, tool := range all {
		names[tool.Name] = true
	}

	// Conflicting tool should be namespaced.
	expected := []string{"desktop/read_file", "train/read_file", "custom_tool", "other_tool"}
	for _, want := range expected {
		if !names[want] {
			t.Errorf("missing tool %q in GetAllTools, got %v", want, names)
		}
	}

	// Verify namespaced lookups work.
	got1, ok1 := cache.GetTool("desktop/read_file")
	if !ok1 {
		t.Fatal("expected desktop/read_file to exist")
	}
	if got1.UpstreamID != "u1" {
		t.Errorf("desktop/read_file UpstreamID = %q, want %q", got1.UpstreamID, "u1")
	}

	got2, ok2 := cache.GetTool("train/read_file")
	if !ok2 {
		t.Fatal("expected train/read_file to exist")
	}
	if got2.UpstreamID != "u2" {
		t.Errorf("train/read_file UpstreamID = %q, want %q", got2.UpstreamID, "u2")
	}

	// Unique tools accessible by bare name.
	_, okCustom := cache.GetTool("custom_tool")
	if !okCustom {
		t.Error("expected custom_tool to be accessible by bare name")
	}
	_, okOther := cache.GetTool("other_tool")
	if !okOther {
		t.Error("expected other_tool to be accessible by bare name")
	}
}

func TestToolCache_NamespaceWithSpecialChars(t *testing.T) {
	cache := NewToolCache()

	// Single upstream with hyphen in name — no conflict, no namespace needed.
	cache.SetToolsForUpstream("u1", []*DiscoveredTool{
		makeToolWithName("read_file", "u1", "my-server"),
	})

	got, ok := cache.GetTool("read_file")
	if !ok {
		t.Fatal("expected read_file to be accessible without namespace (single upstream)")
	}
	if got.Name != "read_file" {
		t.Errorf("Name = %q, want %q", got.Name, "read_file")
	}
	if got.UpstreamName != "my-server" {
		t.Errorf("UpstreamName = %q, want %q", got.UpstreamName, "my-server")
	}
}

func TestToolCache_ThreeServersConflict(t *testing.T) {
	cache := NewToolCache()

	cache.SetToolsForUpstream("u1", []*DiscoveredTool{
		makeToolWithName("read_file", "u1", "alpha"),
	})
	cache.SetToolsForUpstream("u2", []*DiscoveredTool{
		makeToolWithName("read_file", "u2", "beta"),
	})
	cache.SetToolsForUpstream("u3", []*DiscoveredTool{
		makeToolWithName("read_file", "u3", "gamma"),
	})

	all := cache.GetAllTools()
	if len(all) != 3 {
		t.Fatalf("GetAllTools length = %d, want 3", len(all))
	}

	names := make(map[string]bool)
	for _, tool := range all {
		names[tool.Name] = true
	}
	for _, want := range []string{"alpha/read_file", "beta/read_file", "gamma/read_file"} {
		if !names[want] {
			t.Errorf("missing tool %q in GetAllTools, got %v", want, names)
		}
	}

	// Each accessible via namespaced name.
	for _, ns := range []struct {
		name       string
		upstreamID string
	}{
		{"alpha/read_file", "u1"},
		{"beta/read_file", "u2"},
		{"gamma/read_file", "u3"},
	} {
		got, ok := cache.GetTool(ns.name)
		if !ok {
			t.Errorf("expected %q to exist", ns.name)
			continue
		}
		if got.UpstreamID != ns.upstreamID {
			t.Errorf("%q UpstreamID = %q, want %q", ns.name, got.UpstreamID, ns.upstreamID)
		}
	}

	// Bare name is ambiguous.
	ambig, suggestions := cache.IsAmbiguous("read_file")
	if !ambig {
		t.Error("expected read_file to be ambiguous with 3 servers")
	}
	if len(suggestions) != 3 {
		t.Errorf("expected 3 suggestions, got %d: %v", len(suggestions), suggestions)
	}
}

func TestToolCache_ConcurrentSetToolsNamespace(t *testing.T) {
	cache := NewToolCache()

	var wg sync.WaitGroup
	const goroutines = 10

	// Each goroutine registers a "shared" tool and a unique tool.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			uid := fmt.Sprintf("u%d", id)
			cache.SetToolsForUpstream(uid, []*DiscoveredTool{
				makeToolWithName("shared", uid, fmt.Sprintf("srv%d", id)),
				makeToolWithName(fmt.Sprintf("unique_%d", id), uid, fmt.Sprintf("srv%d", id)),
			})
		}(i)
	}
	wg.Wait()

	// After completion, "shared" should be ambiguous.
	ambig, suggestions := cache.IsAmbiguous("shared")
	if !ambig {
		t.Fatal("expected shared to be ambiguous")
	}
	if len(suggestions) != goroutines {
		t.Errorf("expected %d suggestions, got %d", goroutines, len(suggestions))
	}

	// Each unique tool should be accessible by bare name.
	for i := 0; i < goroutines; i++ {
		name := fmt.Sprintf("unique_%d", i)
		_, ok := cache.GetTool(name)
		if !ok {
			t.Errorf("expected %q to be accessible", name)
		}
	}

	// Total: goroutines namespaced "shared" + goroutines unique tools.
	if cache.Count() != goroutines*2 {
		t.Errorf("Count = %d, want %d", cache.Count(), goroutines*2)
	}
}

func TestToolCache_OriginalName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"desktop/read_file", "read_file"},
		{"read_file", "read_file"},
		{"ns/sub/tool", "sub/tool"},
		{"a/b", "b"},
		{"singleslash/", ""},
	}
	for _, tc := range tests {
		got := OriginalName(tc.input)
		if got != tc.want {
			t.Errorf("OriginalName(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestToolCache_DuplicateServerNames(t *testing.T) {
	cache := NewToolCache()

	// Two servers with same UpstreamName="prod" but different IDs.
	cache.SetToolsForUpstream("id1", []*DiscoveredTool{
		makeToolWithName("read_file", "id1", "prod"),
	})
	cache.SetToolsForUpstream("id2", []*DiscoveredTool{
		makeToolWithName("read_file", "id2", "prod"),
	})

	// Since UpstreamName collides, resolved names should include _ID suffix.
	got1, ok1 := cache.GetTool("prod_id1/read_file")
	if !ok1 {
		t.Fatal("expected prod_id1/read_file to exist")
	}
	if got1.UpstreamID != "id1" {
		t.Errorf("prod_id1/read_file UpstreamID = %q, want %q", got1.UpstreamID, "id1")
	}

	got2, ok2 := cache.GetTool("prod_id2/read_file")
	if !ok2 {
		t.Fatal("expected prod_id2/read_file to exist")
	}
	if got2.UpstreamID != "id2" {
		t.Errorf("prod_id2/read_file UpstreamID = %q, want %q", got2.UpstreamID, "id2")
	}

	// Plain "prod/read_file" should NOT resolve (ambiguous upstream name).
	_, okPlain := cache.GetTool("prod/read_file")
	if okPlain {
		t.Error("expected prod/read_file to NOT exist (ambiguous upstream name)")
	}

	// Bare name should be ambiguous.
	ambig, suggestions := cache.IsAmbiguous("read_file")
	if !ambig {
		t.Fatal("expected read_file to be ambiguous")
	}
	if len(suggestions) != 2 {
		t.Errorf("expected 2 suggestions, got %d: %v", len(suggestions), suggestions)
	}

	// Verify GetAllTools returns both with _ID suffix.
	all := cache.GetAllTools()
	if len(all) != 2 {
		t.Fatalf("GetAllTools length = %d, want 2", len(all))
	}
	names := make(map[string]bool)
	for _, tool := range all {
		names[tool.Name] = true
	}
	if !names["prod_id1/read_file"] {
		t.Errorf("missing prod_id1/read_file in GetAllTools, got %v", names)
	}
	if !names["prod_id2/read_file"] {
		t.Errorf("missing prod_id2/read_file in GetAllTools, got %v", names)
	}
}

func TestToolCacheEmpty(t *testing.T) {
	cache := NewToolCache()

	// GetTool on empty cache.
	_, ok := cache.GetTool("anything")
	if ok {
		t.Error("GetTool should return false on empty cache")
	}

	// GetAllTools on empty cache.
	all := cache.GetAllTools()
	if len(all) != 0 {
		t.Errorf("GetAllTools length = %d, want 0", len(all))
	}

	// GetToolsByUpstream on empty cache.
	byUp := cache.GetToolsByUpstream("u1")
	if byUp != nil {
		t.Error("GetToolsByUpstream should return nil on empty cache")
	}

	// Count on empty cache.
	if cache.Count() != 0 {
		t.Errorf("Count = %d, want 0", cache.Count())
	}

	// RemoveUpstream on empty cache should not panic.
	cache.RemoveUpstream("nonexistent")

	// GetConflicts on empty cache.
	if c := cache.GetConflicts(); c != nil {
		t.Error("GetConflicts should return nil on empty cache")
	}

	// ClearConflicts on empty cache should not panic.
	cache.ClearConflicts()
}
