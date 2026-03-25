package action

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"sort"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/event"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/proxy"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
)

// ErrContentBlocked is an alias for proxy.ErrContentBlocked for backward compatibility.
var ErrContentBlocked = proxy.ErrContentBlocked

// WhitelistEntry defines a context-specific exception for content scanning.
type WhitelistEntry struct {
	ID          string             `json:"id"`
	PatternType ContentPatternType `json:"pattern_type"` // which pattern to skip
	Scope       WhitelistScope     `json:"scope"`        // what scope to apply
	Value       string             `json:"value"`        // scope value (path, agent, tool)
}

// WhitelistScope determines what a whitelist entry applies to.
type WhitelistScope string

const (
	WhitelistScopePath  WhitelistScope = "path"  // ignore pattern for specific file path
	WhitelistScopeAgent WhitelistScope = "agent" // ignore for specific agent identity
	WhitelistScopeTool  WhitelistScope = "tool"  // ignore for specific tool name
)

// ContentScanInterceptor scans tool call arguments for sensitive content
// (PII, secrets) before forwarding to the upstream tool server.
// It implements ActionInterceptor and sits in the chain after policy
// evaluation but before the upstream router.
type ContentScanInterceptor struct {
	scanner  *ContentScanner
	next     ActionInterceptor
	logger   *slog.Logger
	enabled  *atomic.Bool
	eventBus event.Bus

	mu        sync.RWMutex
	whitelist []WhitelistEntry
}

// Compile-time check.
var _ ActionInterceptor = (*ContentScanInterceptor)(nil)

// NewContentScanInterceptor creates a new ContentScanInterceptor.
func NewContentScanInterceptor(
	scanner *ContentScanner,
	next ActionInterceptor,
	enabled bool,
	logger *slog.Logger,
) *ContentScanInterceptor {
	e := &atomic.Bool{}
	e.Store(enabled)
	return &ContentScanInterceptor{
		scanner: scanner,
		next:    next,
		logger:  logger,
		enabled: e,
	}
}

// SetEventBus sets the event bus for emitting content scan events.
func (c *ContentScanInterceptor) SetEventBus(bus event.Bus) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.eventBus = bus
}

// SetEnabled updates the enabled state thread-safely.
func (c *ContentScanInterceptor) SetEnabled(enabled bool) {
	c.enabled.Store(enabled)
}

// Enabled returns whether content scanning is active.
func (c *ContentScanInterceptor) Enabled() bool {
	return c.enabled.Load()
}

// SetWhitelist replaces the whitelist entries.
func (c *ContentScanInterceptor) SetWhitelist(entries []WhitelistEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.whitelist = entries
}

// AddWhitelistEntry adds a single whitelist entry.
func (c *ContentScanInterceptor) AddWhitelistEntry(entry WhitelistEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.whitelist = append(c.whitelist, entry)
}

// GetWhitelist returns a copy of the current whitelist.
func (c *ContentScanInterceptor) GetWhitelist() []WhitelistEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]WhitelistEntry, len(c.whitelist))
	copy(result, c.whitelist)
	return result
}

// RemoveWhitelistEntry removes a whitelist entry by ID.
func (c *ContentScanInterceptor) RemoveWhitelistEntry(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, e := range c.whitelist {
		if e.ID == id {
			c.whitelist = append(c.whitelist[:i], c.whitelist[i+1:]...)
			return true
		}
	}
	return false
}

// Intercept scans the action's arguments for sensitive content before
// forwarding to the next interceptor.
// GetPatternActions returns the current action for each pattern type.
func (c *ContentScanInterceptor) GetPatternActions() map[ContentPatternType]ContentPatternAction {
	return c.scanner.GetPatternActions()
}

// SetPatternAction changes the action for a specific pattern type.
func (c *ContentScanInterceptor) SetPatternAction(patternType ContentPatternType, act ContentPatternAction) {
	c.scanner.SetPatternAction(patternType, act)
}

func (c *ContentScanInterceptor) Intercept(ctx context.Context, a *CanonicalAction) (*CanonicalAction, error) {
	if !c.enabled.Load() {
		return c.next.Intercept(ctx, a)
	}

	// Only scan tool calls with arguments.
	if a == nil || a.Type != ActionToolCall || len(a.Arguments) == 0 {
		return c.next.Intercept(ctx, a)
	}

	result := c.scanner.ScanArguments(a.Arguments)
	if !result.Detected {
		return c.next.Intercept(ctx, a)
	}

	// Filter out whitelisted findings.
	filtered := c.filterWhitelisted(result.Findings, a)
	if len(filtered) == 0 {
		return c.next.Intercept(ctx, a)
	}

	// Rebuild result with filtered findings.
	result.Findings = filtered
	result.HasBlock = false
	for _, f := range filtered {
		if f.Action == ContentActionBlock {
			result.HasBlock = true
			break
		}
	}

	// Log and emit events.
	c.logAndEmit(ctx, a, result)

	// Populate scan result holder in context (for AuditInterceptor).
	if holder := audit.ScanResultFromContext(ctx); holder != nil {
		holder.Detections = len(filtered)
		// Deduplicate pattern types for Types field.
		typeSet := make(map[string]bool)
		for _, f := range filtered {
			typeSet[string(f.PatternType)] = true
		}
		types := make([]string, 0, len(typeSet))
		for t := range typeSet {
			types = append(types, t)
		}
		sort.Strings(types)
		holder.Types = strings.Join(types, ",")
		if result.HasBlock {
			holder.Action = "blocked"
		} else {
			holder.Action = "monitored"
		}
	}

	// If any finding requires blocking, reject the request.
	if result.HasBlock {
		patternNames := make([]string, 0, len(filtered))
		for _, f := range filtered {
			if f.Action == ContentActionBlock {
				patternNames = append(patternNames, string(f.PatternType))
			}
		}
		return nil, fmt.Errorf("%w: %s", ErrContentBlocked, strings.Join(patternNames, ", "))
	}

	// Apply masking for findings with mask action.
	hasMask := false
	for _, f := range filtered {
		if f.Action == ContentActionMask {
			hasMask = true
			break
		}
	}
	if hasMask {
		a.Arguments = c.scanner.MaskArguments(a.Arguments)

		// BUG-2 FIX: Re-serialize masked arguments back into the original
		// message's Raw bytes so that the upstream receives masked data.
		// Without this, copyMessages() writes the original unmasked Raw bytes
		// to the upstream, and masking only affects the audit record.
		// This mirrors the pattern used by TransformInterceptor for responses.
		if mcpMsg, ok := a.OriginalMessage.(*mcp.Message); ok && mcpMsg != nil && mcpMsg.Raw != nil {
			if rebuilt, err := rebuildRawWithMaskedArgs(mcpMsg.Raw, a.Arguments); err == nil {
				mcpMsg.Raw = rebuilt
			} else if c.logger != nil {
				c.logger.Warn("content scanning: failed to re-serialize masked arguments into Raw",
					"tool", a.Name,
					"error", err,
				)
			}
		}
	}

	return c.next.Intercept(ctx, a)
}

// filterWhitelisted removes findings that are covered by whitelist entries.
func (c *ContentScanInterceptor) filterWhitelisted(findings []ContentFinding, a *CanonicalAction) []ContentFinding {
	c.mu.RLock()
	whitelist := c.whitelist
	c.mu.RUnlock()

	if len(whitelist) == 0 {
		return findings
	}

	filtered := make([]ContentFinding, 0, len(findings))
	for _, f := range findings {
		if c.isWhitelisted(f, a, whitelist) {
			continue
		}
		filtered = append(filtered, f)
	}
	return filtered
}

func (c *ContentScanInterceptor) isWhitelisted(f ContentFinding, a *CanonicalAction, entries []WhitelistEntry) bool {
	for _, e := range entries {
		if e.PatternType != f.PatternType {
			continue
		}
		switch e.Scope {
		case WhitelistScopeTool:
			if a.Name == e.Value {
				return true
			}
		case WhitelistScopeAgent:
			if a.Identity.ID == e.Value {
				return true
			}
		case WhitelistScopePath:
			// Check if any argument contains the whitelisted path.
			if pathVal, ok := a.Arguments["path"]; ok {
				if pathStr, ok := pathVal.(string); ok && matchGlob(e.Value, pathStr) {
					return true
				}
			}
		}
	}
	return false
}

func matchGlob(pattern, value string) bool {
	matched, err := filepath.Match(pattern, value)
	if err != nil {
		return false
	}
	if matched {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := pattern[:len(pattern)-1]
		return strings.HasPrefix(value, prefix)
	}
	return false
}

// rebuildRawWithMaskedArgs re-serializes the JSON-RPC message Raw bytes with
// the masked arguments. It parses the original Raw, replaces params.arguments
// with the masked map, and returns the re-serialized bytes.
// This ensures that the upstream receives the masked data, not the original.
func rebuildRawWithMaskedArgs(raw []byte, maskedArgs map[string]interface{}) ([]byte, error) {
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}

	paramsRaw, ok := envelope["params"]
	if !ok || paramsRaw == nil {
		return nil, fmt.Errorf("no params field in message")
	}

	var params map[string]json.RawMessage
	if err := json.Unmarshal(paramsRaw, &params); err != nil {
		return nil, fmt.Errorf("unmarshal params: %w", err)
	}

	// Replace arguments with masked version.
	maskedArgsBytes, err := json.Marshal(maskedArgs)
	if err != nil {
		return nil, fmt.Errorf("marshal masked args: %w", err)
	}
	params["arguments"] = maskedArgsBytes

	// Rebuild params into envelope.
	newParamsBytes, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("marshal params: %w", err)
	}
	envelope["params"] = newParamsBytes

	// Rebuild envelope.
	rebuilt, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}
	return rebuilt, nil
}

// logAndEmit logs findings and emits events on the bus.
func (c *ContentScanInterceptor) logAndEmit(ctx context.Context, a *CanonicalAction, result ContentScanResult) {
	typeCounts := make(map[ContentPatternType]int)
	for _, f := range result.Findings {
		typeCounts[f.PatternType]++
	}

	typeStrs := make([]string, 0, len(typeCounts))
	for t, count := range typeCounts {
		typeStrs = append(typeStrs, fmt.Sprintf("%s:%d", t, count))
	}

	if c.logger != nil {
		c.logger.Warn("content scanning: sensitive data detected in arguments",
			"tool", a.Name,
			"identity", a.Identity.ID,
			"findings_count", len(result.Findings),
			"has_block", result.HasBlock,
			"types", strings.Join(typeStrs, ","),
			"scan_duration_ns", result.ScanDurationNs,
		)
	}

	c.mu.RLock()
	bus := c.eventBus
	c.mu.RUnlock()

	if bus == nil {
		return
	}

	// Group by action type for events.
	var hasPII, hasSecret bool
	for _, f := range result.Findings {
		switch f.PatternType {
		case PatternAWSKey, PatternGCPKey, PatternAzureKey, PatternStripe, PatternGitHub, PatternGeneric:
			hasSecret = true
		default:
			hasPII = true
		}
	}

	// Determine enforcement mode for the notification.
	mode := "monitor"
	if result.HasBlock {
		mode = "enforce"
	}

	if hasPII {
		bus.Publish(ctx, event.Event{
			Type:     "content.pii_detected",
			Source:   "content-scanner",
			Severity: event.SeverityWarning,
			Payload: map[string]interface{}{
				"tool":          a.Name,
				"identity_id":   a.Identity.ID,
				"identity_name": a.Identity.Name,
				"findings":      len(result.Findings),
				"types":         typeStrs,
				"direction":     "input",
				"mode":          mode,
			},
			RequiresAction: result.HasBlock,
		})
	}

	if hasSecret {
		bus.Publish(ctx, event.Event{
			Type:     "content.secret_detected",
			Source:   "content-scanner",
			Severity: event.SeverityCritical,
			Payload: map[string]interface{}{
				"tool":          a.Name,
				"identity_id":   a.Identity.ID,
				"identity_name": a.Identity.Name,
				"findings":      len(result.Findings),
				"types":         typeStrs,
				"direction":     "input",
				"mode":          mode,
			},
			RequiresAction: true,
		})
	}
}
