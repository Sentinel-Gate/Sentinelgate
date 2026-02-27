package session

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestDefaultClassifier(t *testing.T) {
	tests := []struct {
		toolName string
		want     CallType
	}{
		// Write patterns — suffix
		{"file_write", CallTypeWrite},
		{"db_create", CallTypeWrite},
		{"record_insert", CallTypeWrite},
		{"field_update", CallTypeWrite},
		{"cache_put", CallTypeWrite},
		{"config_set", CallTypeWrite},
		{"doc_save", CallTypeWrite},
		{"log_append", CallTypeWrite},
		// Write patterns — prefix
		{"write_file", CallTypeWrite},
		{"create_record", CallTypeWrite},
		{"edit_document", CallTypeWrite},
		// Delete patterns — suffix
		{"file_delete", CallTypeDelete},
		{"record_remove", CallTypeDelete},
		{"table_drop", CallTypeDelete},
		// Delete patterns — prefix
		{"delete_file", CallTypeDelete},
		{"remove_record", CallTypeDelete},
		// Read patterns — suffix
		{"file_read", CallTypeRead},
		{"user_get", CallTypeRead},
		{"items_list", CallTypeRead},
		{"docs_search", CallTypeRead},
		{"record_find", CallTypeRead},
		{"data_query", CallTypeRead},
		// Read patterns — prefix
		{"read_file", CallTypeRead},
		{"get_user", CallTypeRead},
		{"list_items", CallTypeRead},
		{"search_docs", CallTypeRead},
		// Other
		{"unknown_tool", CallTypeOther},
		{"process", CallTypeOther},
		{"execute_task", CallTypeOther},
	}

	classifier := DefaultClassifier()
	for _, tt := range tests {
		t.Run(tt.toolName, func(t *testing.T) {
			got := classifier(tt.toolName)
			if got != tt.want {
				t.Errorf("DefaultClassifier(%q) = %q, want %q", tt.toolName, got, tt.want)
			}
		})
	}
}

func TestSessionTracker_RecordCall_IncrementsTotalCalls(t *testing.T) {
	tracker := NewSessionTracker(time.Minute, DefaultClassifier())

	tracker.RecordCall("sess-1", "some_tool", "id-1", "user-1", nil)
	tracker.RecordCall("sess-1", "another_tool", "id-1", "user-1", nil)
	tracker.RecordCall("sess-1", "third_tool", "id-1", "user-1", nil)

	usage, ok := tracker.GetUsage("sess-1")
	if !ok {
		t.Fatal("GetUsage() returned false for tracked session")
	}
	if usage.TotalCalls != 3 {
		t.Errorf("TotalCalls = %d, want 3", usage.TotalCalls)
	}
}

func TestSessionTracker_RecordCall_ClassifiesCallTypes(t *testing.T) {
	tracker := NewSessionTracker(time.Minute, DefaultClassifier())

	tracker.RecordCall("sess-1", "write_file", "id-1", "user-1", nil)
	tracker.RecordCall("sess-1", "read_file", "id-1", "user-1", nil)
	tracker.RecordCall("sess-1", "delete_file", "id-1", "user-1", nil)
	tracker.RecordCall("sess-1", "something_else", "id-1", "user-1", nil)

	usage, ok := tracker.GetUsage("sess-1")
	if !ok {
		t.Fatal("GetUsage() returned false for tracked session")
	}
	if usage.WriteCalls != 1 {
		t.Errorf("WriteCalls = %d, want 1", usage.WriteCalls)
	}
	if usage.ReadCalls != 1 {
		t.Errorf("ReadCalls = %d, want 1", usage.ReadCalls)
	}
	if usage.DeleteCalls != 1 {
		t.Errorf("DeleteCalls = %d, want 1", usage.DeleteCalls)
	}
	if usage.TotalCalls != 4 {
		t.Errorf("TotalCalls = %d, want 4", usage.TotalCalls)
	}
}

func TestSessionTracker_RecordCall_TracksByToolName(t *testing.T) {
	tracker := NewSessionTracker(time.Minute, DefaultClassifier())

	tracker.RecordCall("sess-1", "read_file", "id-1", "user-1", nil)
	tracker.RecordCall("sess-1", "read_file", "id-1", "user-1", nil)
	tracker.RecordCall("sess-1", "write_file", "id-1", "user-1", nil)

	usage, ok := tracker.GetUsage("sess-1")
	if !ok {
		t.Fatal("GetUsage() returned false for tracked session")
	}
	if usage.CallsByToolName["read_file"] != 2 {
		t.Errorf("CallsByToolName[read_file] = %d, want 2", usage.CallsByToolName["read_file"])
	}
	if usage.CallsByToolName["write_file"] != 1 {
		t.Errorf("CallsByToolName[write_file] = %d, want 1", usage.CallsByToolName["write_file"])
	}
}

func TestSessionTracker_GetUsage_NonExistentSession(t *testing.T) {
	tracker := NewSessionTracker(time.Minute, DefaultClassifier())

	usage, ok := tracker.GetUsage("nonexistent")
	if ok {
		t.Error("GetUsage() returned true for nonexistent session")
	}
	if usage.TotalCalls != 0 {
		t.Errorf("TotalCalls = %d, want 0", usage.TotalCalls)
	}
}

func TestSessionTracker_SlidingWindow_ExpiresOldEntries(t *testing.T) {
	// Use a very short window for testing
	tracker := NewSessionTracker(50*time.Millisecond, DefaultClassifier())

	tracker.RecordCall("sess-1", "tool-a", "id-1", "user-1", nil)
	tracker.RecordCall("sess-1", "tool-b", "id-1", "user-1", nil)

	// Verify we have 2 window calls
	usage, _ := tracker.GetUsage("sess-1")
	if usage.WindowCalls != 2 {
		t.Errorf("WindowCalls before sleep = %d, want 2", usage.WindowCalls)
	}

	// Wait for entries to expire
	time.Sleep(80 * time.Millisecond)

	// Record one more call
	tracker.RecordCall("sess-1", "tool-c", "id-1", "user-1", nil)

	usage, _ = tracker.GetUsage("sess-1")
	if usage.WindowCalls != 1 {
		t.Errorf("WindowCalls after sleep = %d, want 1 (only new call)", usage.WindowCalls)
	}
	// Total should still have all 3
	if usage.TotalCalls != 3 {
		t.Errorf("TotalCalls = %d, want 3", usage.TotalCalls)
	}
}

func TestSessionTracker_RemoveSession(t *testing.T) {
	tracker := NewSessionTracker(time.Minute, DefaultClassifier())

	tracker.RecordCall("sess-1", "tool", "id-1", "user-1", nil)
	tracker.RemoveSession("sess-1")

	_, ok := tracker.GetUsage("sess-1")
	if ok {
		t.Error("GetUsage() returned true after RemoveSession")
	}
}

func TestSessionTracker_ActiveSessions_ReturnsAll(t *testing.T) {
	tracker := NewSessionTracker(time.Minute, DefaultClassifier())

	tracker.RecordCall("sess-1", "tool-a", "id-1", "Alice", nil)
	tracker.RecordCall("sess-2", "tool-b", "id-2", "Bob", nil)
	tracker.RecordCall("sess-3", "tool-c", "id-3", "Charlie", nil)

	sessions := tracker.ActiveSessions()
	if len(sessions) != 3 {
		t.Fatalf("ActiveSessions() returned %d sessions, want 3", len(sessions))
	}

	// Build a map for easier lookup
	byID := make(map[string]ActiveSessionInfo)
	for _, s := range sessions {
		byID[s.SessionID] = s
	}

	// Verify identity info
	s1 := byID["sess-1"]
	if s1.IdentityID != "id-1" || s1.IdentityName != "Alice" {
		t.Errorf("sess-1 identity = (%q, %q), want (id-1, Alice)", s1.IdentityID, s1.IdentityName)
	}
	s2 := byID["sess-2"]
	if s2.IdentityID != "id-2" || s2.IdentityName != "Bob" {
		t.Errorf("sess-2 identity = (%q, %q), want (id-2, Bob)", s2.IdentityID, s2.IdentityName)
	}
}

func TestSessionTracker_ConcurrentAccess(t *testing.T) {
	tracker := NewSessionTracker(time.Minute, DefaultClassifier())

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			sessID := fmt.Sprintf("sess-%d", n%3) // 3 sessions, shared across goroutines
			for j := 0; j < 100; j++ {
				tracker.RecordCall(sessID, "tool", fmt.Sprintf("id-%d", n), fmt.Sprintf("user-%d", n), nil)
			}
		}(i)
	}
	wg.Wait()

	// Verify no panic and reasonable totals
	sessions := tracker.ActiveSessions()
	if len(sessions) != 3 {
		t.Errorf("ActiveSessions() = %d, want 3", len(sessions))
	}

	totalCalls := int64(0)
	for _, s := range sessions {
		totalCalls += s.Usage.TotalCalls
	}
	if totalCalls != 1000 { // 10 goroutines * 100 calls
		t.Errorf("total calls across sessions = %d, want 1000", totalCalls)
	}
}

func TestSessionTracker_RecordCall_StoresIdentityInfo(t *testing.T) {
	tracker := NewSessionTracker(time.Minute, DefaultClassifier())

	// First call sets identity info
	tracker.RecordCall("sess-1", "tool-a", "id-1", "Alice", nil)
	// Subsequent call with different identity should NOT overwrite
	tracker.RecordCall("sess-1", "tool-b", "id-2", "Bob", nil)

	sessions := tracker.ActiveSessions()
	if len(sessions) != 1 {
		t.Fatalf("ActiveSessions() returned %d sessions, want 1", len(sessions))
	}

	s := sessions[0]
	if s.IdentityID != "id-1" {
		t.Errorf("IdentityID = %q, want %q (should not be overwritten)", s.IdentityID, "id-1")
	}
	if s.IdentityName != "Alice" {
		t.Errorf("IdentityName = %q, want %q (should not be overwritten)", s.IdentityName, "Alice")
	}
}

func TestSessionTracker_ActionHistory_Basic(t *testing.T) {
	tracker := NewSessionTracker(time.Minute, DefaultClassifier())

	tracker.RecordCall("sess-1", "read_file", "id-1", "user-1", []string{"path"})
	tracker.RecordCall("sess-1", "write_file", "id-1", "user-1", []string{"content", "path"})
	tracker.RecordCall("sess-1", "delete_file", "id-1", "user-1", nil)

	history, ok := tracker.GetActionHistory("sess-1")
	if !ok {
		t.Fatal("GetActionHistory() returned false for tracked session")
	}
	if len(history) != 3 {
		t.Fatalf("action history length = %d, want 3", len(history))
	}

	// Verify order and content
	if history[0].ToolName != "read_file" {
		t.Errorf("history[0].ToolName = %q, want %q", history[0].ToolName, "read_file")
	}
	if history[0].CallType != CallTypeRead {
		t.Errorf("history[0].CallType = %q, want %q", history[0].CallType, CallTypeRead)
	}
	if len(history[0].ArgKeys) != 1 || history[0].ArgKeys[0] != "path" {
		t.Errorf("history[0].ArgKeys = %v, want [path]", history[0].ArgKeys)
	}
	if history[0].Timestamp.IsZero() {
		t.Error("history[0].Timestamp is zero")
	}

	if history[1].ToolName != "write_file" {
		t.Errorf("history[1].ToolName = %q, want %q", history[1].ToolName, "write_file")
	}
	if history[1].CallType != CallTypeWrite {
		t.Errorf("history[1].CallType = %q, want %q", history[1].CallType, CallTypeWrite)
	}
	if len(history[1].ArgKeys) != 2 {
		t.Errorf("history[1].ArgKeys length = %d, want 2", len(history[1].ArgKeys))
	}

	if history[2].ToolName != "delete_file" {
		t.Errorf("history[2].ToolName = %q, want %q", history[2].ToolName, "delete_file")
	}
	if history[2].CallType != CallTypeDelete {
		t.Errorf("history[2].CallType = %q, want %q", history[2].CallType, CallTypeDelete)
	}
	if history[2].ArgKeys != nil {
		t.Errorf("history[2].ArgKeys = %v, want nil", history[2].ArgKeys)
	}

	// Timestamps should be in order
	if history[1].Timestamp.Before(history[0].Timestamp) {
		t.Error("history[1].Timestamp is before history[0].Timestamp")
	}
	if history[2].Timestamp.Before(history[1].Timestamp) {
		t.Error("history[2].Timestamp is before history[1].Timestamp")
	}
}

func TestSessionTracker_ActionHistory_FIFOEviction(t *testing.T) {
	tracker := NewSessionTracker(time.Minute, DefaultClassifier())

	// Record 1001 calls
	for i := 0; i < MaxActionHistory+1; i++ {
		toolName := fmt.Sprintf("tool_%d", i)
		tracker.RecordCall("sess-1", toolName, "id-1", "user-1", nil)
	}

	history, ok := tracker.GetActionHistory("sess-1")
	if !ok {
		t.Fatal("GetActionHistory() returned false for tracked session")
	}
	if len(history) != MaxActionHistory {
		t.Fatalf("action history length = %d, want %d", len(history), MaxActionHistory)
	}

	// First record should be the 2nd call (index 1), since index 0 was evicted
	if history[0].ToolName != "tool_1" {
		t.Errorf("history[0].ToolName = %q, want %q (oldest should be evicted)", history[0].ToolName, "tool_1")
	}

	// Last record should be the most recent call
	if history[MaxActionHistory-1].ToolName != fmt.Sprintf("tool_%d", MaxActionHistory) {
		t.Errorf("history[last].ToolName = %q, want %q", history[MaxActionHistory-1].ToolName, fmt.Sprintf("tool_%d", MaxActionHistory))
	}
}

func TestSessionTracker_ActionSet(t *testing.T) {
	tracker := NewSessionTracker(time.Minute, DefaultClassifier())

	tracker.RecordCall("sess-1", "read_file", "id-1", "user-1", nil)
	tracker.RecordCall("sess-1", "write_file", "id-1", "user-1", nil)
	tracker.RecordCall("sess-1", "delete_file", "id-1", "user-1", nil)

	actionSet, ok := tracker.GetActionSet("sess-1")
	if !ok {
		t.Fatal("GetActionSet() returned false for tracked session")
	}
	if len(actionSet) != 3 {
		t.Fatalf("action set size = %d, want 3", len(actionSet))
	}
	for _, tool := range []string{"read_file", "write_file", "delete_file"} {
		if !actionSet[tool] {
			t.Errorf("action set missing %q", tool)
		}
	}

	// Record a duplicate: set size should remain 3
	tracker.RecordCall("sess-1", "read_file", "id-1", "user-1", nil)
	actionSet, _ = tracker.GetActionSet("sess-1")
	if len(actionSet) != 3 {
		t.Errorf("action set size after duplicate = %d, want 3", len(actionSet))
	}
}

func TestSessionTracker_ArgKeySet(t *testing.T) {
	tracker := NewSessionTracker(time.Minute, DefaultClassifier())

	tracker.RecordCall("sess-1", "write_file", "id-1", "user-1", []string{"content", "path"})
	tracker.RecordCall("sess-1", "read_file", "id-1", "user-1", []string{"mode", "path"})

	argKeySet, ok := tracker.GetArgKeySet("sess-1")
	if !ok {
		t.Fatal("GetArgKeySet() returned false for tracked session")
	}
	if len(argKeySet) != 3 {
		t.Fatalf("arg key set size = %d, want 3", len(argKeySet))
	}
	for _, key := range []string{"path", "content", "mode"} {
		if !argKeySet[key] {
			t.Errorf("arg key set missing %q", key)
		}
	}
}

func TestSessionTracker_ActionHistory_DeepCopy(t *testing.T) {
	tracker := NewSessionTracker(time.Minute, DefaultClassifier())

	tracker.RecordCall("sess-1", "read_file", "id-1", "user-1", []string{"path"})
	tracker.RecordCall("sess-1", "write_file", "id-1", "user-1", []string{"content"})

	// Get a copy
	history, ok := tracker.GetActionHistory("sess-1")
	if !ok {
		t.Fatal("GetActionHistory() returned false for tracked session")
	}

	// Mutate the returned slice
	history[0].ToolName = "MUTATED"
	history[0].ArgKeys[0] = "MUTATED"
	_ = append(history, ActionRecord{ToolName: "extra"}) //nolint:gocritic // intentional: verify append on copy doesn't mutate original

	// Get again and verify original is unchanged
	original, _ := tracker.GetActionHistory("sess-1")
	if len(original) != 2 {
		t.Fatalf("original length = %d after mutation, want 2", len(original))
	}
	if original[0].ToolName != "read_file" {
		t.Errorf("original[0].ToolName = %q after mutation, want %q", original[0].ToolName, "read_file")
	}
	if original[0].ArgKeys[0] != "path" {
		t.Errorf("original[0].ArgKeys[0] = %q after mutation, want %q", original[0].ArgKeys[0], "path")
	}
}

func TestSessionTracker_ActionHistory_Concurrent(t *testing.T) {
	tracker := NewSessionTracker(time.Minute, DefaultClassifier())

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				toolName := fmt.Sprintf("tool_%d_%d", n, j)
				tracker.RecordCall("sess-1", toolName, fmt.Sprintf("id-%d", n), fmt.Sprintf("user-%d", n), []string{"arg"})
			}
		}(i)
	}
	wg.Wait()

	// Total: 10 goroutines * 100 calls = 1000, which is exactly MaxActionHistory
	history, ok := tracker.GetActionHistory("sess-1")
	if !ok {
		t.Fatal("GetActionHistory() returned false for tracked session")
	}
	if len(history) > MaxActionHistory {
		t.Errorf("action history length = %d, exceeds MaxActionHistory=%d", len(history), MaxActionHistory)
	}
	// With exactly 1000 calls, the length should be exactly 1000
	if len(history) != MaxActionHistory {
		t.Errorf("action history length = %d, want %d", len(history), MaxActionHistory)
	}

	// Verify action set has all unique tool names
	actionSet, _ := tracker.GetActionSet("sess-1")
	if len(actionSet) != 1000 {
		t.Errorf("action set size = %d, want 1000 (all unique tool names)", len(actionSet))
	}

	// Verify arg key set has "arg"
	argKeySet, _ := tracker.GetArgKeySet("sess-1")
	if len(argKeySet) != 1 || !argKeySet["arg"] {
		t.Errorf("arg key set = %v, want {arg: true}", argKeySet)
	}
}
