package transform

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/action"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/audit"
	"github.com/Sentinel-Gate/Sentinelgate/pkg/mcp"
)

// Compile-time check that TransformInterceptor implements ActionInterceptor.
var _ action.ActionInterceptor = (*TransformInterceptor)(nil)

// TransformInterceptor applies transform rules to tool call responses.
// It sits in the ActionInterceptor chain between the outbound interceptor
// and the response scan interceptor.
//
// Dry-run rules short-circuit before upstream execution (the tool call
// never reaches the upstream). Other rules (redact, truncate, inject, mask)
// are applied after the upstream returns a response.
type TransformInterceptor struct {
	store    TransformStore
	executor *TransformExecutor
	next     action.ActionInterceptor
	logger   *slog.Logger
}

// NewTransformInterceptor creates a new TransformInterceptor.
func NewTransformInterceptor(
	store TransformStore,
	executor *TransformExecutor,
	next action.ActionInterceptor,
	logger *slog.Logger,
) *TransformInterceptor {
	if logger == nil {
		logger = slog.Default()
	}
	return &TransformInterceptor{
		store:    store,
		executor: executor,
		next:     next,
		logger:   logger,
	}
}

// Intercept processes a CanonicalAction through the transform pipeline.
func (t *TransformInterceptor) Intercept(ctx context.Context, a *action.CanonicalAction) (*action.CanonicalAction, error) {
	// Only transform tool calls.
	if a.Type != action.ActionToolCall {
		return t.next.Intercept(ctx, a)
	}

	// Load matching rules from store.
	matchedRules, err := t.loadMatchingRules(ctx, a.Name)
	if err != nil {
		t.logger.Warn("failed to load transform rules", "error", err)
		// Fail open: proceed without transforms.
		return t.next.Intercept(ctx, a)
	}

	// Pre-upstream: check for dry-run rules.
	for _, rule := range matchedRules {
		if rule.Type == TransformDryRun && rule.Enabled {
			return t.handleDryRun(ctx, a, &rule)
		}
	}

	// Call next interceptor (upstream router executes the tool).
	result, err := t.next.Intercept(ctx, a)
	if err != nil {
		return result, err
	}
	if result == nil {
		return nil, nil
	}

	// Post-upstream: apply transforms to the response.
	return t.applyTransforms(ctx, result, matchedRules)
}

// handleDryRun short-circuits the chain with a synthetic response.
func (t *TransformInterceptor) handleDryRun(ctx context.Context, a *action.CanonicalAction, rule *TransformRule) (*action.CanonicalAction, error) {
	responseBody := rule.Config.Response
	if responseBody == "" {
		responseBody = `{"success": true, "dry_run": true}`
	}

	// Extract request message for building response with matching ID.
	reqMsg, _ := a.OriginalMessage.(*mcp.Message)
	syntheticMsg, err := buildSyntheticResponse(reqMsg, responseBody)
	if err != nil {
		return nil, fmt.Errorf("build synthetic response: %w", err)
	}

	// Build result action with synthetic response.
	result := &action.CanonicalAction{
		Type:            a.Type,
		Name:            a.Name,
		Protocol:        a.Protocol,
		OriginalMessage: syntheticMsg,
		Metadata:        make(map[string]interface{}),
	}

	// Record transform result in metadata for audit.
	transformResult := TransformResult{
		RuleID:   rule.ID,
		RuleName: rule.Name,
		Type:     TransformDryRun,
		Applied:  true,
		Detail:   "dry-run: call intercepted before upstream",
	}
	result.Metadata["transform_results"] = []TransformResult{transformResult}

	// Populate audit context holder.
	if holder := audit.TransformResultFromContext(ctx); holder != nil {
		holder.Results = []audit.TransformApplied{{
			RuleID:   rule.ID,
			RuleName: rule.Name,
			Type:     string(TransformDryRun),
			Detail:   "dry-run: call intercepted before upstream",
		}}
	}

	t.logger.Info("transform: dry-run intercepted tool call",
		"tool", a.Name,
		"rule", rule.Name,
	)

	return result, nil
}

// applyTransforms applies post-upstream transforms to a response.
func (t *TransformInterceptor) applyTransforms(ctx context.Context, result *action.CanonicalAction, matchedRules []TransformRule) (*action.CanonicalAction, error) {
	// Extract MCP message from result.
	mcpMsg, ok := result.OriginalMessage.(*mcp.Message)
	if !ok || mcpMsg == nil {
		return result, nil
	}

	// Only transform server-to-client responses.
	if mcpMsg.Direction != mcp.ServerToClient {
		return result, nil
	}

	// Skip binary content (XFRM-11).
	if IsBinaryContent(mcpMsg.Raw) {
		return result, nil
	}

	// Filter to enabled, non-dry-run rules and sort by priority.
	var applicableRules []TransformRule
	for _, rule := range matchedRules {
		if rule.Enabled && rule.Type != TransformDryRun {
			applicableRules = append(applicableRules, rule)
		}
	}
	if len(applicableRules) == 0 {
		return result, nil
	}

	// Parse the response to extract text content.
	modified, allResults, changed := t.transformResponseContent(mcpMsg.Raw, applicableRules)
	if !changed {
		// Store results even if nothing changed (for audit trail).
		t.populateMetadata(ctx, result, allResults)
		return result, nil
	}

	// Update the MCP message with transformed content.
	mcpMsg.Raw = modified
	result.OriginalMessage = mcpMsg

	// Populate metadata and audit context.
	t.populateMetadata(ctx, result, allResults)

	return result, nil
}

// transformResponseContent parses raw JSON, applies transforms to text content,
// and returns the modified JSON. Returns the modified bytes, transform results,
// and whether any change occurred.
func (t *TransformInterceptor) transformResponseContent(raw []byte, rules []TransformRule) ([]byte, []TransformResult, bool) {
	// Parse the raw JSON to extract result field.
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return raw, nil, false
	}

	resultRaw, ok := envelope["result"]
	if !ok || resultRaw == nil {
		return raw, nil, false
	}

	// Try to parse as MCP tool result format: {"content": [{"type":"text","text":"..."}]}
	var toolResult struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(resultRaw, &toolResult); err == nil && len(toolResult.Content) > 0 {
		return t.transformMCPContent(raw, envelope, toolResult.Content, rules)
	}

	// Try as plain string result.
	var strResult string
	if err := json.Unmarshal(resultRaw, &strResult); err == nil && strResult != "" {
		transformed, results := t.executor.Apply(strResult, rules)
		if !hasApplied(results) {
			return raw, results, false
		}
		// Rebuild the envelope with the transformed string.
		newResult, err := json.Marshal(transformed)
		if err != nil {
			return raw, results, false
		}
		envelope["result"] = newResult
		rebuilt, err := json.Marshal(envelope)
		if err != nil {
			return raw, results, false
		}
		return rebuilt, results, true
	}

	return raw, nil, false
}

// contentItem represents a content array element for JSON marshaling.
type contentItem struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// transformMCPContent applies transforms to each text item in an MCP content array.
func (t *TransformInterceptor) transformMCPContent(
	raw []byte,
	envelope map[string]json.RawMessage,
	content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	},
	rules []TransformRule,
) ([]byte, []TransformResult, bool) {
	var allResults []TransformResult
	changed := false

	items := make([]contentItem, len(content))
	for i, c := range content {
		items[i] = contentItem{Type: c.Type, Text: c.Text}
		if c.Type == "text" || c.Text != "" {
			transformed, results := t.executor.Apply(c.Text, rules)
			allResults = append(allResults, results...)
			if transformed != c.Text {
				items[i].Text = transformed
				changed = true
			}
		}
	}

	if !changed {
		return raw, allResults, false
	}

	// Rebuild the result with transformed content.
	newToolResult := struct {
		Content []contentItem `json:"content"`
	}{Content: items}

	newResultBytes, err := json.Marshal(newToolResult)
	if err != nil {
		return raw, allResults, false
	}
	envelope["result"] = newResultBytes

	rebuilt, err := json.Marshal(envelope)
	if err != nil {
		return raw, allResults, false
	}
	return rebuilt, allResults, true
}

// loadMatchingRules loads all enabled rules from the store that match the tool name.
func (t *TransformInterceptor) loadMatchingRules(ctx context.Context, toolName string) ([]TransformRule, error) {
	allRules, err := t.store.List(ctx)
	if err != nil {
		return nil, err
	}

	var matched []TransformRule
	for _, r := range allRules {
		if r.MatchesTool(toolName) {
			matched = append(matched, *r)
		}
	}
	return SortByPriority(matched), nil
}

// populateMetadata stores transform results in action metadata and audit context.
func (t *TransformInterceptor) populateMetadata(ctx context.Context, result *action.CanonicalAction, results []TransformResult) {
	if result.Metadata == nil {
		result.Metadata = make(map[string]interface{})
	}
	result.Metadata["transform_results"] = results

	// Populate audit context holder.
	if holder := audit.TransformResultFromContext(ctx); holder != nil {
		applied := make([]audit.TransformApplied, 0, len(results))
		for _, r := range results {
			if r.Applied {
				applied = append(applied, audit.TransformApplied{
					RuleID:   r.RuleID,
					RuleName: r.RuleName,
					Type:     string(r.Type),
					Detail:   r.Detail,
				})
			}
		}
		holder.Results = applied
	}
}

// buildSyntheticResponse creates a JSON-RPC response message with MCP tool result format.
func buildSyntheticResponse(requestMsg *mcp.Message, responseBody string) (*mcp.Message, error) {
	// Extract request ID (defaults to 1 if no request message).
	var rawID json.RawMessage
	if requestMsg != nil {
		rawID = requestMsg.RawID()
	}
	if rawID == nil {
		rawID = json.RawMessage(`1`)
	}

	// Build MCP tool result format.
	toolResult := struct {
		Content []contentItem `json:"content"`
	}{
		Content: []contentItem{{Type: "text", Text: responseBody}},
	}
	resultBytes, err := json.Marshal(toolResult)
	if err != nil {
		return nil, fmt.Errorf("marshal tool result: %w", err)
	}

	// Build JSON-RPC response envelope.
	response := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      rawID,
		"result":  json.RawMessage(resultBytes),
	}
	responseBytes, err := json.Marshal(response)
	if err != nil {
		return nil, fmt.Errorf("marshal response envelope: %w", err)
	}

	return &mcp.Message{
		Raw:       responseBytes,
		Direction: mcp.ServerToClient,
	}, nil
}

// hasApplied returns true if any TransformResult has Applied=true.
func hasApplied(results []TransformResult) bool {
	for _, r := range results {
		if r.Applied {
			return true
		}
	}
	return false
}

