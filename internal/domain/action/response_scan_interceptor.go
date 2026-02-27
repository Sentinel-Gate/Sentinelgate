package action

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
)

// ErrResponseBlocked is returned when response content scanning detects
// prompt injection in enforce mode.
var ErrResponseBlocked = errors.New("response blocked by content scanning")

// ResponseScanInterceptor scans MCP tool results for prompt injection
// before forwarding them to the agent. It implements ActionInterceptor
// and sits between the upstream router and the policy interceptor in
// the chain.
//
// In monitor mode, detections are logged but responses pass through.
// In enforce mode, responses containing injection patterns are blocked.
type ResponseScanInterceptor struct {
	scanner *ResponseScanner
	next    ActionInterceptor
	logger  *slog.Logger
	mode    *atomic.Value // stores ScanMode string
	enabled *atomic.Bool
}

// Compile-time check that ResponseScanInterceptor implements ActionInterceptor.
var _ ActionInterceptor = (*ResponseScanInterceptor)(nil)

// NewResponseScanInterceptor creates a new ResponseScanInterceptor.
func NewResponseScanInterceptor(
	scanner *ResponseScanner,
	next ActionInterceptor,
	mode ScanMode,
	enabled bool,
	logger *slog.Logger,
) *ResponseScanInterceptor {
	modeVal := &atomic.Value{}
	modeVal.Store(mode)
	enabledVal := &atomic.Bool{}
	enabledVal.Store(enabled)

	return &ResponseScanInterceptor{
		scanner: scanner,
		next:    next,
		logger:  logger,
		mode:    modeVal,
		enabled: enabledVal,
	}
}

// Intercept processes a CanonicalAction through the chain and scans
// server-to-client responses for prompt injection.
func (r *ResponseScanInterceptor) Intercept(ctx context.Context, a *CanonicalAction) (*CanonicalAction, error) {
	// If scanning is disabled, pass through immediately.
	if !r.enabled.Load() {
		return r.next.Intercept(ctx, a)
	}

	// Let the inner chain run first (upstream router executes the tool).
	result, err := r.next.Intercept(ctx, a)
	if err != nil {
		return result, err
	}
	if result == nil {
		return nil, nil
	}

	// Check if this is a server-to-client response worth scanning.
	mcpMsg, ok := result.OriginalMessage.(*mcp.Message)
	if !ok {
		// Non-MCP message, skip scanning.
		return result, nil
	}
	if mcpMsg.Direction != mcp.ServerToClient {
		// Not a server response, skip scanning.
		return result, nil
	}

	// Extract and scan response content from the mcp.Message.
	scanResult := r.scanResponseContent(mcpMsg)
	if !scanResult.Detected {
		return result, nil
	}

	// Build pattern names for logging.
	patternNames := make([]string, 0, len(scanResult.Findings))
	seen := make(map[string]bool)
	for _, f := range scanResult.Findings {
		if !seen[f.PatternName] {
			patternNames = append(patternNames, f.PatternName)
			seen[f.PatternName] = true
		}
	}

	currentMode := r.Mode()
	method := mcpMsg.Method()

	r.logger.Warn("response content scanning: prompt injection detected",
		"mode", string(currentMode),
		"findings_count", len(scanResult.Findings),
		"scan_duration_ns", scanResult.ScanDurationNs,
		"method", method,
		"pattern_names", strings.Join(patternNames, ","),
	)

	// Populate scan result holder in context (for AuditInterceptor).
	if holder := audit.ScanResultFromContext(ctx); holder != nil {
		holder.Detections = len(scanResult.Findings)
		// Deduplicate categories for Types field.
		catSet := make(map[string]bool)
		for _, f := range scanResult.Findings {
			catSet[f.PatternCategory] = true
		}
		cats := make([]string, 0, len(catSet))
		for c := range catSet {
			cats = append(cats, c)
		}
		sort.Strings(cats)
		holder.Types = strings.Join(cats, ",")
		if currentMode == ScanModeEnforce {
			holder.Action = "blocked"
		} else {
			holder.Action = "monitored"
		}
	}

	// In monitor mode: log only, return the result.
	if currentMode == ScanModeMonitor {
		return result, nil
	}

	// In enforce mode: block the response.
	return nil, fmt.Errorf("%w: detected patterns: %s",
		ErrResponseBlocked,
		strings.Join(patternNames, ", "),
	)
}

// scanResponseContent extracts scannable content from an mcp.Message
// and runs the scanner against it.
func (r *ResponseScanInterceptor) scanResponseContent(msg *mcp.Message) ScanResult {
	if msg.Raw == nil {
		return ScanResult{}
	}

	// Parse the raw JSON to extract the result field.
	var envelope struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(msg.Raw, &envelope); err != nil || envelope.Result == nil {
		// No result field, fall back to scanning entire raw content.
		return r.scanner.Scan(string(msg.Raw))
	}

	// Try to parse result as MCP tool result format with content array.
	var toolResult struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(envelope.Result, &toolResult); err == nil && len(toolResult.Content) > 0 {
		// Scan each text content item.
		var allFindings []ScanFinding
		for _, c := range toolResult.Content {
			if c.Type == "text" || c.Text != "" {
				sr := r.scanner.Scan(c.Text)
				if sr.Detected {
					allFindings = append(allFindings, sr.Findings...)
				}
			}
		}
		if len(allFindings) > 0 {
			return ScanResult{
				Detected: true,
				Findings: allFindings,
			}
		}
		return ScanResult{}
	}

	// Try scanning as a plain string.
	var strResult string
	if err := json.Unmarshal(envelope.Result, &strResult); err == nil {
		return r.scanner.Scan(strResult)
	}

	// Fallback: scan entire result as generic JSON.
	var genericResult interface{}
	if err := json.Unmarshal(envelope.Result, &genericResult); err == nil {
		return r.scanner.ScanJSON(genericResult)
	}

	return ScanResult{}
}

// SetMode updates the scan mode thread-safely.
func (r *ResponseScanInterceptor) SetMode(mode ScanMode) {
	r.mode.Store(mode)
}

// SetEnabled updates the enabled state thread-safely.
func (r *ResponseScanInterceptor) SetEnabled(enabled bool) {
	r.enabled.Store(enabled)
}

// Mode returns the current scan mode.
func (r *ResponseScanInterceptor) Mode() ScanMode {
	return r.mode.Load().(ScanMode)
}

// Enabled returns whether scanning is currently active.
func (r *ResponseScanInterceptor) Enabled() bool {
	return r.enabled.Load()
}
