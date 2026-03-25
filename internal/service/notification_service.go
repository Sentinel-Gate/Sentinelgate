package service

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/event"
)

// Notification is a user-facing notification created from an event.
type Notification struct {
	ID             string         `json:"id"`
	Type           string         `json:"type"`            // event type
	Source         string         `json:"source"`          // which upgrade generated it
	Severity       string         `json:"severity"`        // "critical", "warning", "info"
	Title          string         `json:"title"`           // human-readable title
	Message        string         `json:"message"`         // detail text
	Timestamp      time.Time      `json:"timestamp"`
	RequiresAction bool           `json:"requires_action"` // shows in Action Queue
	Dismissed      bool           `json:"dismissed"`       // hidden from UI
	Actions        []NotifAction  `json:"actions,omitempty"`
	Payload        any            `json:"payload,omitempty"` // original event payload
	Count          int            `json:"count"`             // number of grouped events (1 = single)
}

// dedupWindow is the time window within which identical notifications are grouped.
const dedupWindow = 5 * time.Minute

// NotifAction is a button the admin can click on a notification.
type NotifAction struct {
	Label  string `json:"label"`  // e.g. "Accept", "Block", "View"
	Action string `json:"action"` // e.g. "accept_change", "quarantine", "navigate"
	Target string `json:"target"` // e.g. tool name, URL fragment
}

// NotificationService manages notifications backed by an in-memory ring buffer.
// It subscribes to the Event Bus and converts events into user-facing notifications.
type NotificationService struct {
	mu      sync.RWMutex
	items   []Notification
	maxSize int
	nextID  uint64

	// SSE subscribers.
	sseMu       sync.RWMutex
	sseClients  map[uint64]chan Notification
	sseNextID   uint64

	// H-8: stopped flag prevents sending to closed SSE channels after Stop().
	stopped bool

	// Lifecycle: unsubscribe from event bus on Stop.
	unsubscribe func()
}

// NewNotificationService creates a notification service with a ring buffer of maxSize.
func NewNotificationService(maxSize int) *NotificationService {
	if maxSize <= 0 {
		maxSize = 500
	}
	return &NotificationService{
		items:      make([]Notification, 0, maxSize),
		maxSize:    maxSize,
		sseClients: make(map[uint64]chan Notification),
	}
}

// SubscribeToBus registers this service as a consumer of all events on the bus.
// The unsubscribe function is stored internally and called by Stop().
func (s *NotificationService) SubscribeToBus(bus event.Bus) {
	unsub := bus.SubscribeAll(func(ctx context.Context, evt event.Event) {
		notif := s.eventToNotification(evt)
		s.Add(notif)
	})
	s.mu.Lock()
	s.unsubscribe = unsub
	s.mu.Unlock()
}

// Stop unsubscribes from the event bus and closes all SSE client channels.
func (s *NotificationService) Stop() {
	s.mu.Lock()
	unsub := s.unsubscribe
	s.unsubscribe = nil
	s.mu.Unlock()

	if unsub != nil {
		unsub()
	}

	// H-8: Set stopped flag before closing channels to prevent Add() from
	// sending to closed channels if an in-flight event handler races with Stop().
	s.sseMu.Lock()
	s.stopped = true
	for id, ch := range s.sseClients {
		delete(s.sseClients, id)
		close(ch)
	}
	s.sseMu.Unlock()
}

// Add inserts a notification and broadcasts it to SSE clients.
// If a non-dismissed notification with the same Type+Source exists within
// the dedup window, the existing one is updated (count incremented,
// timestamp refreshed) instead of creating a new entry.
func (s *NotificationService) Add(n Notification) {
	if n.Count == 0 {
		n.Count = 1
	}
	s.mu.Lock()

	// Dedup: look for recent non-dismissed notification with same Type+Source.
	cutoff := time.Now().Add(-dedupWindow)
	deduped := false
	for i := len(s.items) - 1; i >= 0; i-- {
		existing := &s.items[i]
		if existing.Timestamp.Before(cutoff) {
			continue // outside window; don't break since in-place timestamp updates may violate ordering
		}
		if !existing.Dismissed && existing.Type == n.Type && existing.Source == n.Source {
			existing.Count++
			existing.Timestamp = n.Timestamp
			existing.Message = n.Message // keep latest message
			deduped = true
			n = *existing // broadcast the updated notification
			break
		}
	}

	if !deduped {
		if n.ID == "" {
			s.nextID++
			n.ID = "notif_" + strconv.FormatUint(s.nextID, 10)
		}
		s.items = append(s.items, n)
		if len(s.items) > s.maxSize {
			kept := make([]Notification, s.maxSize)
			copy(kept, s.items[len(s.items)-s.maxSize:])
			s.items = kept
		}
	}
	s.mu.Unlock()

	// H-8: Broadcast to SSE clients only if not stopped.
	s.sseMu.RLock()
	if !s.stopped {
		for _, ch := range s.sseClients {
			select {
			case ch <- n:
			default: // drop if client is slow
			}
		}
	}
	s.sseMu.RUnlock()
}

// List returns notifications, most recent first. If onlyActive is true, filters out dismissed.
func (s *NotificationService) List(onlyActive bool) []Notification {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]Notification, 0, len(s.items))
	for i := len(s.items) - 1; i >= 0; i-- {
		if onlyActive && s.items[i].Dismissed {
			continue
		}
		result = append(result, s.items[i])
	}
	return result
}

// PendingActionCount returns the number of non-dismissed notifications requiring action.
func (s *NotificationService) PendingActionCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for i := range s.items {
		if s.items[i].RequiresAction && !s.items[i].Dismissed {
			count++
		}
	}
	return count
}

// TotalActiveCount returns the number of non-dismissed notifications.
func (s *NotificationService) TotalActiveCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for i := range s.items {
		if !s.items[i].Dismissed {
			count++
		}
	}
	return count
}

// Dismiss marks a notification as dismissed.
func (s *NotificationService) Dismiss(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.items {
		if s.items[i].ID == id {
			s.items[i].Dismissed = true
			return true
		}
	}
	return false
}

// DismissAll marks all notifications as dismissed.
func (s *NotificationService) DismissAll() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.items {
		s.items[i].Dismissed = true
	}
}

// ClearAll removes all notifications from the ring buffer.
// Unlike DismissAll (which marks items dismissed but keeps them in memory),
// this reclaims memory entirely. Used by factory reset.
func (s *NotificationService) ClearAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = make([]Notification, 0, s.maxSize)
	s.nextID = 0
}

// SubscribeSSE registers an SSE client and returns (channel, unsubscribe).
func (s *NotificationService) SubscribeSSE() (<-chan Notification, func()) {
	ch := make(chan Notification, 50)
	s.sseMu.Lock()
	s.sseNextID++
	id := s.sseNextID
	s.sseClients[id] = ch
	s.sseMu.Unlock()

	return ch, func() {
		s.sseMu.Lock()
		defer s.sseMu.Unlock()
		if _, exists := s.sseClients[id]; exists {
			delete(s.sseClients, id)
			close(ch)
		}
	}
}

// eventToNotification converts an Event Bus event into a user-facing notification.
func (s *NotificationService) eventToNotification(evt event.Event) Notification {
	title, message, actions := formatNotification(evt)
	return Notification{
		Type:           evt.Type,
		Source:         evt.Source,
		Severity:       evt.Severity.String(),
		Title:          title,
		Message:        message,
		Timestamp:      evt.Timestamp,
		RequiresAction: evt.RequiresAction,
		Actions:        actions,
		Payload:        evt.Payload,
	}
}

// resolveIdentityName extracts identity_name from event payload,
// falling back to identity_id if name is not available.
func resolveIdentityName(p map[string]interface{}) string {
	if name, _ := p["identity_name"].(string); name != "" {
		return name
	}
	id, _ := p["identity_id"].(string)
	return id
}

// formatNotification produces human-readable title/message/actions for known event types.
func formatNotification(evt event.Event) (title, message string, actions []NotifAction) {
	switch evt.Type {
	case "tool.changed":
		title = "Tool Definition Changed"
		toolName := ""
		if p, ok := evt.Payload.(map[string]string); ok {
			toolName = p["tool_name"]
			message = toolName + " on " + p["upstream"] + " has been modified"
		} else {
			message = "A tool definition has changed"
		}
		actions = []NotifAction{
			{Label: "View Diff", Action: "view_diff", Target: toolName},
			{Label: "Accept", Action: "accept_change"},
			{Label: "Quarantine", Action: "quarantine"},
		}
	case "tool.new":
		title = "New Tool Discovered"
		if p, ok := evt.Payload.(map[string]string); ok {
			message = p["tool_name"] + " registered by " + p["upstream"]
		} else {
			message = "A new tool has been registered"
		}
	case "tool.collision":
		title = "Tool Name Collision"
		if p, ok := evt.Payload.(map[string]string); ok {
			message = p["tool_name"] + ": conflict between " + p["winner"] + " and " + p["skipped"]
		} else {
			message = "Two upstreams registered tools with the same name"
		}
		actions = []NotifAction{
			{Label: "View Details", Action: "navigate", Target: "#/tools?conflicts=true"},
		}
	case "tool.quarantined":
		title = "Tool Quarantined"
		if p, ok := evt.Payload.(map[string]string); ok {
			message = p["tool_name"] + " has been quarantined"
		} else {
			message = "A tool has been quarantined"
		}
		actions = []NotifAction{
			{Label: "View", Action: "navigate", Target: "#/tools?quarantine=true"},
		}
	case "evidence.chain_broken":
		title = "Evidence Chain Broken"
		message = "The cryptographic evidence chain has been tampered with"
		actions = []NotifAction{
			{Label: "Verify", Action: "navigate", Target: "#/audit"},
		}
	case "content.pii_detected":
		title = "PII Detected in Tool Arguments"
		if p, ok := evt.Payload.(map[string]interface{}); ok {
			tool, ok2 := p["tool"].(string)
			if !ok2 || tool == "" {
				tool = "unknown"
			}
			identity := resolveIdentityName(p)
			if identity == "" {
				identity = "unknown"
			}
			mode, _ := p["mode"].(string)
			if mode == "enforce" {
				message = "Blocked request — PII detected in " + tool + " from " + identity + ". Review in Activity."
			} else {
				message = "Detected PII in " + tool + " arguments from " + identity
			}
		} else {
			message = "PII detected in tool call arguments"
		}
		actions = []NotifAction{
			{Label: "Review", Action: "navigate", Target: "#/security?tab=scanning"},
			{Label: "Whitelist", Action: "content_whitelist"},
		}
	case "content.secret_detected":
		title = "Secret/API Key Detected"
		if p, ok := evt.Payload.(map[string]interface{}); ok {
			tool, ok2 := p["tool"].(string)
			if !ok2 || tool == "" {
				tool = "unknown"
			}
			identity := resolveIdentityName(p)
			if identity == "" {
				identity = "unknown"
			}
			mode, _ := p["mode"].(string)
			if mode == "enforce" {
				message = "Blocked request — secret found in " + tool + " from " + identity + ". Review in Activity."
			} else {
				message = "Detected secret in " + tool + " arguments from " + identity
			}
		} else {
			message = "Secret detected in tool call arguments"
		}
		actions = []NotifAction{
			{Label: "Review", Action: "navigate", Target: "#/security?tab=scanning"},
		}
	case "content.ipi_detected":
		title = "Prompt Injection Detected in Response"
		if p, ok := evt.Payload.(map[string]interface{}); ok {
			tool, ok2 := p["tool"].(string)
			if !ok2 || tool == "" {
				tool = "unknown"
			}
			identity := resolveIdentityName(p)
			if identity == "" {
				identity = "unknown"
			}
			mode, _ := p["mode"].(string)
			if mode == "enforce" {
				message = "Blocked response — IPI detected in " + tool + " from " + identity
			} else {
				message = "Detected prompt injection in " + tool + " response from " + identity
			}
		} else {
			message = "Indirect prompt injection detected"
		}
		actions = []NotifAction{
			{Label: "Review", Action: "navigate", Target: "#/security?tab=scanning"},
		}
	case "content.whitelist_added":
		title = "Whitelist Exception Added"
		if p, ok := evt.Payload.(map[string]string); ok {
			message = p["pattern_type"] + " for " + p["scope"] + " " + p["value"]
		} else {
			message = "A new whitelist exception has been added"
		}
		actions = []NotifAction{
			{Label: "View", Action: "navigate", Target: "#/security?tab=scanning"},
		}
	case "content.whitelist_removed":
		title = "Whitelist Exception Removed"
		if p, ok := evt.Payload.(map[string]string); ok {
			message = p["pattern_type"] + " for " + p["scope"] + " " + p["value"]
		} else {
			message = "A whitelist exception has been removed"
		}
		actions = []NotifAction{
			{Label: "View", Action: "navigate", Target: "#/security?tab=scanning"},
		}
	case "approval.hold":
		title = "Approval Required"
		if p, ok := evt.Payload.(map[string]interface{}); ok {
			tool, ok2 := p["tool_name"].(string)
			if !ok2 || tool == "" {
				tool = "unknown"
			}
			identity, ok3 := p["identity_name"].(string)
			if !ok3 || identity == "" {
				identity = "unknown"
			}
			approvalID, _ := p["approval_id"].(string)
			message = identity + " wants to use " + tool
			actions = []NotifAction{
				{Label: "Review", Action: "approval_review", Target: approvalID},
				{Label: "Approve", Action: "approval_approve", Target: approvalID},
				{Label: "Deny", Action: "approval_deny", Target: approvalID},
			}
		} else {
			message = "A tool call requires human approval"
		}
	case "approval.approved":
		title = "Approval Granted"
		if p, ok := evt.Payload.(map[string]interface{}); ok {
			tool, ok2 := p["tool_name"].(string)
			if !ok2 || tool == "" {
				tool = "unknown"
			}
			identity, ok3 := p["identity_name"].(string)
			if !ok3 || identity == "" {
				identity = "unknown"
			}
			message = tool + " approved for " + identity
		} else {
			message = "A pending approval has been granted"
		}
	case "approval.rejected":
		title = "Approval Denied"
		if p, ok := evt.Payload.(map[string]interface{}); ok {
			tool, ok2 := p["tool_name"].(string)
			if !ok2 || tool == "" {
				tool = "unknown"
			}
			identity, ok3 := p["identity_name"].(string)
			if !ok3 || identity == "" {
				identity = "unknown"
			}
			reason, _ := p["reason"].(string)
			message = tool + " denied for " + identity
			if reason != "" {
				message += ": " + reason
			}
		} else {
			message = "A pending approval has been denied"
		}
	case "approval.timeout":
		title = "Approval Timed Out"
		if p, ok := evt.Payload.(map[string]interface{}); ok {
			tool, ok2 := p["tool_name"].(string)
			if !ok2 || tool == "" {
				tool = "unknown"
			}
			identity, ok3 := p["identity_name"].(string)
			if !ok3 || identity == "" {
				identity = "unknown"
			}
			message = tool + " from " + identity + " timed out"
		} else {
			message = "An approval request has timed out"
		}
	case "drift.anomaly":
		title = "Behavioral Drift Detected"
		if p, ok := evt.Payload.(map[string]interface{}); ok {
			identity := resolveIdentityName(p)
			score, _ := p["drift_score"].(float64)
			message = identity + " — drift score " + fmtFloat(score, 2)
			if rawAnomalies, ok2 := p["anomalies"].([]interface{}); ok2 && len(rawAnomalies) > 0 {
				if a, ok3 := rawAnomalies[0].(map[string]interface{}); ok3 {
					desc, _ := a["description"].(string)
					if desc != "" {
						message += ": " + desc
					}
				}
			}
			actions = []NotifAction{
				{Label: "View", Action: "navigate", Target: "#/agents?drift=" + identity},
				{Label: "Create Policy", Action: "drift_policy", Target: identity},
			}
		} else {
			message = "An agent's behavior has deviated from baseline"
		}
	case "drift.baseline_reset":
		title = "Drift Baseline Reset"
		if p, ok := evt.Payload.(map[string]interface{}); ok {
			identity := resolveIdentityName(p)
			message = "Baseline reset for " + identity
		} else {
			message = "A drift baseline has been reset"
		}
	case "health.alert":
		title = "Agent Health Alert"
		if p, ok := evt.Payload.(map[string]interface{}); ok {
			identity := resolveIdentityName(p)
			status, _ := p["status"].(string)
			denyRate, _ := p["deny_rate"].(float64)
			errorRate, _ := p["error_rate"].(float64)
			driftScore, _ := p["drift_score"].(float64)

			var reasons []string
			if denyRate >= 0.5 {
				reasons = append(reasons, fmt.Sprintf("%.0f%% calls denied", denyRate*100))
			}
			if errorRate >= 0.1 {
				reasons = append(reasons, fmt.Sprintf("%.0f%% error rate", errorRate*100))
			}
			if driftScore >= 0.5 {
				reasons = append(reasons, fmt.Sprintf("drift score %.1f", driftScore))
			}

			if identity != "" {
				message = "Identity " + identity + " — status " + status
			} else {
				message = "Status: " + status
			}
			if len(reasons) > 0 {
				message += ": " + strings.Join(reasons, ", ")
			}
		} else {
			message = "An agent health issue has been detected"
		}
		actions = []NotifAction{
			{Label: "View Details", Action: "navigate", Target: "#/agents"},
		}
	case "permissions.gap_detected":
		title = "Permission Gap Detected"
		if p, ok := evt.Payload.(map[string]interface{}); ok {
			identity := resolveIdentityName(p)
			score, _ := p["least_priv_score"].(float64)
			// L-34: JSON unmarshaling produces float64 for numbers; handle both int and float64.
			var gapCount int
			switch v := p["gap_count"].(type) {
			case int:
				gapCount = v
			case float64:
				gapCount = int(v)
			}
			message = identity + " — least privilege score " + fmtFloat(score, 0) + "%"
			if gapCount > 0 {
				message += " (" + itoa(gapCount) + " over-privileged tools)"
			}
			identityID, _ := p["identity_id"].(string)
			actions = []NotifAction{
				{Label: "View Health Map", Action: "navigate", Target: "#/permissions?identity=" + identityID},
				{Label: "Apply Suggestions", Action: "navigate", Target: "#/permissions?identity=" + identityID + "&apply=true"},
			}
		} else {
			message = "Permission gaps detected for an agent"
		}
	case "permissions.auto_tighten_applied":
		title = "Auto-Tighten Applied"
		if p, ok := evt.Payload.(map[string]interface{}); ok {
			identity := resolveIdentityName(p)
			count, _ := p["count"].(int)
			message = itoa(count) + " tool permissions tightened for " + identity
		} else {
			message = "Permissions have been auto-tightened"
		}
		actions = []NotifAction{
			{Label: "Review", Action: "navigate", Target: "#/permissions"},
		}
	case "redteam.scan_complete":
		title = "Red Team Scan Complete"
		if p, ok := evt.Payload.(map[string]interface{}); ok {
			rate, _ := p["block_rate"].(float64)
			message = "Block rate " + fmtFloat(rate, 0) + "%"
			if vulns, ok := p["vulnerabilities"].(int); ok && vulns > 0 {
				message += " — " + itoa(vulns) + " vulnerabilities found"
			}
		} else {
			message = "Red team scan completed"
		}
		actions = []NotifAction{
			{Label: "View Report", Action: "navigate", Target: "#/redteam"},
		}
	case "finops.budget_warning":
		title = "Budget Warning"
		if p, ok := evt.Payload.(map[string]interface{}); ok {
			identity := resolveIdentityName(p)
			pct, _ := p["percentage"].(float64)
			message = identity + " at " + fmtFloat(pct, 0) + "% of budget"
		} else {
			message = "An identity is approaching its budget limit"
		}
		actions = []NotifAction{
			{Label: "View Costs", Action: "navigate", Target: "#/finops"},
		}
	case "finops.budget_exceeded":
		title = "Budget Exceeded"
		if p, ok := evt.Payload.(map[string]interface{}); ok {
			identity := resolveIdentityName(p)
			spent, _ := p["spent"].(float64)
			budget, _ := p["budget"].(float64)
			message = identity + " spent $" + fmtFloat(spent, 2) + " / $" + fmtFloat(budget, 2)
		} else {
			message = "An identity has exceeded its budget"
		}
		actions = []NotifAction{
			{Label: "View Costs", Action: "navigate", Target: "#/finops"},
		}
	default:
		// Generic formatting for unknown event types.
		title = evt.Type
		if m, ok := evt.Payload.(string); ok {
			message = m
		} else {
			message = "Event from " + evt.Source
		}
	}
	return
}

// fmtFloat formats a float with the given decimal places using the standard library.
func fmtFloat(v float64, decimals int) string {
	return strconv.FormatFloat(v, 'f', decimals, 64)
}

// itoa converts an integer to a string using the standard library.
func itoa(n int) string {
	return strconv.Itoa(n)
}
