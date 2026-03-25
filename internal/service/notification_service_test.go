package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/event"
)

func TestNotificationService_AddAndList(t *testing.T) {
	svc := NewNotificationService(100)

	svc.Add(Notification{Title: "Test 1", Severity: "info"})
	svc.Add(Notification{Title: "Test 2", Severity: "warning"})

	list := svc.List(false)
	if len(list) != 2 {
		t.Fatalf("list len = %d, want 2", len(list))
	}
	// Most recent first.
	if list[0].Title != "Test 2" {
		t.Errorf("first item = %q, want 'Test 2'", list[0].Title)
	}
}

func TestNotificationService_AutoID(t *testing.T) {
	svc := NewNotificationService(100)

	svc.Add(Notification{Title: "A"})
	svc.Add(Notification{Title: "B"})

	list := svc.List(false)
	if list[0].ID == list[1].ID {
		t.Error("notifications should have unique IDs")
	}
	if list[0].ID == "" || list[1].ID == "" {
		t.Error("IDs should not be empty")
	}
}

func TestNotificationService_Dismiss(t *testing.T) {
	svc := NewNotificationService(100)

	svc.Add(Notification{Title: "Keep"})
	svc.Add(Notification{Title: "Dismiss"})

	all := svc.List(false)
	dismissID := all[0].ID // most recent = "Dismiss"

	if !svc.Dismiss(dismissID) {
		t.Fatal("Dismiss returned false")
	}

	active := svc.List(true) // only active
	if len(active) != 1 {
		t.Fatalf("active len = %d, want 1", len(active))
	}
	if active[0].Title != "Keep" {
		t.Errorf("remaining = %q, want 'Keep'", active[0].Title)
	}
}

func TestNotificationService_DismissAll(t *testing.T) {
	svc := NewNotificationService(100)

	svc.Add(Notification{Title: "A"})
	svc.Add(Notification{Title: "B"})

	svc.DismissAll()

	active := svc.List(true)
	if len(active) != 0 {
		t.Errorf("active len = %d, want 0", len(active))
	}
}

func TestNotificationService_PendingActionCount(t *testing.T) {
	svc := NewNotificationService(100)

	svc.Add(Notification{Title: "Info", RequiresAction: false})
	svc.Add(Notification{Title: "Action 1", RequiresAction: true})
	svc.Add(Notification{Title: "Action 2", RequiresAction: true})

	if count := svc.PendingActionCount(); count != 2 {
		t.Errorf("PendingActionCount = %d, want 2", count)
	}

	// Dismiss one action.
	all := svc.List(false)
	for _, n := range all {
		if n.Title == "Action 1" {
			svc.Dismiss(n.ID)
			break
		}
	}

	if count := svc.PendingActionCount(); count != 1 {
		t.Errorf("PendingActionCount after dismiss = %d, want 1", count)
	}
}

func TestNotificationService_RingBuffer(t *testing.T) {
	svc := NewNotificationService(3)

	svc.Add(Notification{Title: "A"})
	svc.Add(Notification{Title: "B"})
	svc.Add(Notification{Title: "C"})
	svc.Add(Notification{Title: "D"}) // A should be evicted

	list := svc.List(false)
	if len(list) != 3 {
		t.Fatalf("list len = %d, want 3", len(list))
	}
	// Should have B, C, D (A evicted).
	titles := make(map[string]bool)
	for _, n := range list {
		titles[n.Title] = true
	}
	if titles["A"] {
		t.Error("A should have been evicted")
	}
	if !titles["D"] {
		t.Error("D should be present")
	}
}

func TestNotificationService_SubscribeToBus(t *testing.T) {
	bus := event.NewBus(100)
	bus.Start()
	defer bus.Stop()

	svc := NewNotificationService(100)
	svc.SubscribeToBus(bus)
	defer svc.Stop()

	bus.Publish(context.Background(), event.Event{
		Type:     "tool.changed",
		Source:   "tool-integrity",
		Severity: event.SeverityWarning,
		Payload: map[string]string{
			"tool_name": "read_file",
			"upstream":  "finance-mcp",
		},
		RequiresAction: true,
	})

	// Poll until the notification is delivered instead of using a fixed sleep.
	deadline := time.After(2 * time.Second)
	for {
		list := svc.List(true)
		if len(list) == 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for notification; list len = %d, want 1", len(svc.List(true)))
		case <-time.After(10 * time.Millisecond):
		}
	}

	list := svc.List(true)

	n := list[0]
	if n.Type != "tool.changed" {
		t.Errorf("type = %q, want 'tool.changed'", n.Type)
	}
	if n.Title != "Tool Definition Changed" {
		t.Errorf("title = %q, want 'Tool Definition Changed'", n.Title)
	}
	if !n.RequiresAction {
		t.Error("should require action")
	}
	if len(n.Actions) == 0 {
		t.Error("should have actions (View Diff, Accept, Quarantine)")
	}
}

func TestNotificationService_SSE(t *testing.T) {
	svc := NewNotificationService(100)

	ch, unsub := svc.SubscribeSSE()
	defer unsub()

	svc.Add(Notification{Title: "SSE Test"})

	select {
	case n := <-ch:
		if n.Title != "SSE Test" {
			t.Errorf("SSE received %q, want 'SSE Test'", n.Title)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for SSE notification")
	}
}

func TestNotificationService_DismissNotFound(t *testing.T) {
	svc := NewNotificationService(100)
	if svc.Dismiss("nonexistent") {
		t.Error("Dismiss should return false for nonexistent ID")
	}
}

func TestNotificationService_WhitelistAddedEvent(t *testing.T) {
	bus := event.NewBus(100)
	bus.Start()
	defer bus.Stop()

	svc := NewNotificationService(100)
	svc.SubscribeToBus(bus)
	defer svc.Stop()

	bus.Publish(context.Background(), event.Event{
		Type:     "content.whitelist_added",
		Source:   "content-scanning",
		Severity: event.SeverityInfo,
		Payload: map[string]string{
			"pattern_type": "email",
			"scope":        "tool",
			"value":        "read_file",
		},
	})

	// Poll until the notification is delivered instead of using a fixed sleep.
	deadline := time.After(2 * time.Second)
	for {
		list := svc.List(false)
		if len(list) == 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for notification; list len = %d, want 1", len(svc.List(false)))
		case <-time.After(10 * time.Millisecond):
		}
	}

	list := svc.List(false)

	n := list[0]
	if n.Type != "content.whitelist_added" {
		t.Errorf("type = %q, want content.whitelist_added", n.Type)
	}
	if n.Title != "Whitelist Exception Added" {
		t.Errorf("title = %q, want 'Whitelist Exception Added'", n.Title)
	}
	if n.Message != "email for tool read_file" {
		t.Errorf("message = %q, want 'email for tool read_file'", n.Message)
	}
	if n.Severity != "info" {
		t.Errorf("severity = %q, want 'info'", n.Severity)
	}
	if len(n.Actions) == 0 {
		t.Error("should have actions")
	}
	if n.Actions[0].Label != "View" {
		t.Errorf("action label = %q, want 'View'", n.Actions[0].Label)
	}
}

// --- Wave 4 Tests: Notification deduplication ---

func TestNotificationService_DeduplicatesSameType(t *testing.T) {
	svc := NewNotificationService(100)

	// Add 5 notifications with same Type+Source within dedup window
	for i := 0; i < 5; i++ {
		svc.Add(Notification{
			Type:      "health.alert",
			Source:    "health-monitor",
			Severity:  "warning",
			Title:     "Agent Health Alert",
			Message:   "Status critical",
			Timestamp: time.Now(),
		})
	}

	list := svc.List(false)
	if len(list) != 1 {
		t.Fatalf("list len = %d, want 1 (deduped)", len(list))
	}
	if list[0].Count != 5 {
		t.Errorf("Count = %d, want 5", list[0].Count)
	}
}

func TestNotificationService_DoesNotDeduplicateDifferentTypes(t *testing.T) {
	svc := NewNotificationService(100)

	svc.Add(Notification{
		Type:      "health.alert",
		Source:    "health-monitor",
		Severity:  "warning",
		Title:     "Health Alert",
		Message:   "Alert",
		Timestamp: time.Now(),
	})
	svc.Add(Notification{
		Type:      "tool.changed",
		Source:    "health-monitor",
		Severity:  "info",
		Title:     "Tool Changed",
		Message:   "Changed",
		Timestamp: time.Now(),
	})

	list := svc.List(false)
	if len(list) != 2 {
		t.Fatalf("list len = %d, want 2 (different types, no dedup)", len(list))
	}
}

func TestNotificationService_DeduplicationWindowExpires(t *testing.T) {
	svc := NewNotificationService(100)

	// Add a notification with a timestamp outside the dedup window (>5 min ago)
	svc.Add(Notification{
		Type:      "health.alert",
		Source:    "health-monitor",
		Severity:  "warning",
		Title:     "Old Alert",
		Message:   "Old",
		Timestamp: time.Now().Add(-6 * time.Minute),
	})

	// Add another with same Type+Source but within a new window (now)
	svc.Add(Notification{
		Type:      "health.alert",
		Source:    "health-monitor",
		Severity:  "warning",
		Title:     "New Alert",
		Message:   "New",
		Timestamp: time.Now(),
	})

	list := svc.List(false)
	if len(list) != 2 {
		t.Fatalf("list len = %d, want 2 (dedup window expired)", len(list))
	}
}

func TestNotificationService_WhitelistRemovedEvent(t *testing.T) {
	bus := event.NewBus(100)
	bus.Start()
	defer bus.Stop()

	svc := NewNotificationService(100)
	svc.SubscribeToBus(bus)
	defer svc.Stop()

	bus.Publish(context.Background(), event.Event{
		Type:     "content.whitelist_removed",
		Source:   "content-scanning",
		Severity: event.SeverityInfo,
		Payload: map[string]string{
			"pattern_type": "credit_card",
			"scope":        "agent",
			"value":        "billing-agent",
		},
	})

	// Poll until the notification is delivered instead of using a fixed sleep.
	deadline := time.After(2 * time.Second)
	for {
		list := svc.List(false)
		if len(list) == 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for notification; list len = %d, want 1", len(svc.List(false)))
		case <-time.After(10 * time.Millisecond):
		}
	}

	list := svc.List(false)

	n := list[0]
	if n.Type != "content.whitelist_removed" {
		t.Errorf("type = %q, want content.whitelist_removed", n.Type)
	}
	if n.Title != "Whitelist Exception Removed" {
		t.Errorf("title = %q, want 'Whitelist Exception Removed'", n.Title)
	}
	if n.Message != "credit_card for agent billing-agent" {
		t.Errorf("message = %q, want 'credit_card for agent billing-agent'", n.Message)
	}
	if n.Severity != "info" {
		t.Errorf("severity = %q, want 'info'", n.Severity)
	}
	if len(n.Actions) == 0 {
		t.Error("should have actions")
	}
	if n.Actions[0].Target != "#/security?tab=scanning" {
		t.Errorf("action target = %q, want '#/security?tab=scanning'", n.Actions[0].Target)
	}
}

// TestNotificationService_ContentScanMonitorVsEnforce verifies that content scan
// notifications differentiate between monitor mode ("Detected...") and enforce
// mode ("Blocked request...") based on the "mode" field in the event payload.
func TestNotificationService_ContentScanMonitorVsEnforce(t *testing.T) {
	bus := event.NewBus(100)
	bus.Start()
	defer bus.Stop()

	svc := NewNotificationService(100)
	svc.SubscribeToBus(bus)
	defer svc.Stop()

	// Emit monitor-mode PII detection
	bus.Publish(context.Background(), event.Event{
		Type:     "content.pii_detected",
		Source:   "content-scanner",
		Severity: event.SeverityWarning,
		Payload: map[string]interface{}{
			"tool":          "write_file",
			"identity_id":   "agent-1",
			"identity_name": "test-agent",
			"findings":      2,
			"mode":          "monitor",
		},
		RequiresAction: false,
	})

	// Emit enforce-mode secret detection
	bus.Publish(context.Background(), event.Event{
		Type:     "content.secret_detected",
		Source:   "content-scanner",
		Severity: event.SeverityCritical,
		Payload: map[string]interface{}{
			"tool":          "read_file",
			"identity_id":   "agent-2",
			"identity_name": "attacker",
			"findings":      1,
			"mode":          "enforce",
		},
		RequiresAction: true,
	})

	// Wait for both notifications
	deadline := time.After(2 * time.Second)
	for {
		list := svc.List(true)
		if len(list) >= 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for 2 notifications; got %d", len(svc.List(true)))
		case <-time.After(10 * time.Millisecond):
		}
	}

	list := svc.List(true)

	// Find the PII notification (monitor mode)
	var monitorNotif, enforceNotif *Notification
	for i := range list {
		if list[i].Type == "content.pii_detected" {
			monitorNotif = &list[i]
		}
		if list[i].Type == "content.secret_detected" {
			enforceNotif = &list[i]
		}
	}

	if monitorNotif == nil {
		t.Fatal("expected content.pii_detected notification")
	}
	if strings.Contains(monitorNotif.Message, "Blocked") {
		t.Errorf("monitor-mode notification should say 'Detected', not 'Blocked'; got: %s", monitorNotif.Message)
	}
	if !strings.Contains(monitorNotif.Message, "Detected") {
		t.Errorf("monitor-mode notification should contain 'Detected'; got: %s", monitorNotif.Message)
	}

	if enforceNotif == nil {
		t.Fatal("expected content.secret_detected notification")
	}
	if !strings.Contains(enforceNotif.Message, "Blocked request") {
		t.Errorf("enforce-mode notification should contain 'Blocked request'; got: %s", enforceNotif.Message)
	}
}
