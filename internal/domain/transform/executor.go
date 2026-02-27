package transform

import (
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"unicode/utf8"
)

// TransformExecutor applies a chain of transform rules to text content.
type TransformExecutor struct {
	logger     *slog.Logger
	regexCache map[string]*regexp.Regexp
	cacheMu    sync.RWMutex
}

// NewTransformExecutor creates a new executor with the given logger.
func NewTransformExecutor(logger *slog.Logger) *TransformExecutor {
	if logger == nil {
		logger = slog.Default()
	}
	return &TransformExecutor{
		logger:     logger,
		regexCache: make(map[string]*regexp.Regexp),
	}
}

// getOrCompileRegex returns a compiled regex from the cache, or compiles and caches it.
func (e *TransformExecutor) getOrCompileRegex(pattern string) (*regexp.Regexp, error) {
	e.cacheMu.RLock()
	if re, ok := e.regexCache[pattern]; ok {
		e.cacheMu.RUnlock()
		return re, nil
	}
	e.cacheMu.RUnlock()

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	e.cacheMu.Lock()
	e.regexCache[pattern] = re
	e.cacheMu.Unlock()
	return re, nil
}

// Apply takes a text response and a list of transform rules, sorts them by
// priority, and applies each enabled rule in order. Returns the transformed
// text and a slice of TransformResult describing what was applied.
func (e *TransformExecutor) Apply(text string, rules []TransformRule) (string, []TransformResult) {
	sorted := SortByPriority(rules)
	var results []TransformResult

	for _, rule := range sorted {
		if !rule.Enabled {
			continue
		}

		var result TransformResult
		result.RuleID = rule.ID
		result.RuleName = rule.Name
		result.Type = rule.Type

		switch rule.Type {
		case TransformRedact:
			text, result = e.applyRedact(text, rule)
		case TransformTruncate:
			text, result = e.applyTruncate(text, rule)
		case TransformInject:
			text, result = e.applyInject(text, rule)
		case TransformMask:
			text, result = e.applyMask(text, rule)
		case TransformDryRun:
			// Dry-run is handled at the pipeline level, not in Apply.
			result.Applied = false
			result.Detail = "dry-run handled at pipeline level"
		default:
			e.logger.Warn("unknown transform type", "type", rule.Type, "rule", rule.Name)
			result.Applied = false
			result.Detail = fmt.Sprintf("unknown type: %s", rule.Type)
		}

		results = append(results, result)
	}

	return text, results
}

// applyRedact replaces all regex-matched patterns with the configured replacement.
func (e *TransformExecutor) applyRedact(text string, rule TransformRule) (string, TransformResult) {
	result := TransformResult{
		RuleID:   rule.ID,
		RuleName: rule.Name,
		Type:     TransformRedact,
	}

	replacement := rule.Config.Replacement
	if replacement == "" {
		replacement = "[REDACTED]"
	}

	totalMatches := 0
	for _, pattern := range rule.Config.Patterns {
		re, err := e.getOrCompileRegex(pattern)
		if err != nil {
			e.logger.Warn("skipping invalid redact pattern", "pattern", pattern, "error", err)
			continue
		}
		matches := re.FindAllStringIndex(text, -1)
		totalMatches += len(matches)
		text = re.ReplaceAllString(text, replacement)
	}

	result.Applied = totalMatches > 0
	result.Detail = fmt.Sprintf("%d matches redacted", totalMatches)
	return text, result
}

// applyTruncate limits response length by bytes or lines.
func (e *TransformExecutor) applyTruncate(text string, rule TransformRule) (string, TransformResult) {
	result := TransformResult{
		RuleID:   rule.ID,
		RuleName: rule.Name,
		Type:     TransformTruncate,
	}

	suffix := rule.Config.Suffix
	if suffix == "" {
		suffix = "\n... [truncated]"
	}

	truncated := false
	detail := ""

	// Apply byte limit first, respecting UTF-8 rune boundaries.
	if rule.Config.MaxBytes > 0 && len(text) > rule.Config.MaxBytes {
		truncAt := rule.Config.MaxBytes
		for truncAt > 0 && !utf8.RuneStart(text[truncAt]) {
			truncAt--
		}
		text = text[:truncAt] + suffix
		truncated = true
		detail = fmt.Sprintf("truncated to %d bytes", truncAt)
	}

	// Apply line limit
	if rule.Config.MaxLines > 0 {
		lines := strings.Split(text, "\n")
		if len(lines) > rule.Config.MaxLines {
			text = strings.Join(lines[:rule.Config.MaxLines], "\n") + suffix
			truncated = true
			if detail != "" {
				detail += " and "
			}
			detail += fmt.Sprintf("truncated to %d lines", rule.Config.MaxLines)
		}
	}

	result.Applied = truncated
	if !truncated {
		detail = "within limits, no truncation"
	}
	result.Detail = detail
	return text, result
}

// applyInject prepends and/or appends text to the response.
func (e *TransformExecutor) applyInject(text string, rule TransformRule) (string, TransformResult) {
	result := TransformResult{
		RuleID:   rule.ID,
		RuleName: rule.Name,
		Type:     TransformInject,
	}

	prependLen := 0
	appendLen := 0

	if rule.Config.Prepend != "" {
		prependLen = len(rule.Config.Prepend)
		text = rule.Config.Prepend + "\n" + text
	}
	if rule.Config.Append != "" {
		appendLen = len(rule.Config.Append)
		text = text + "\n" + rule.Config.Append
	}

	result.Applied = prependLen > 0 || appendLen > 0
	result.Detail = fmt.Sprintf("prepended %d chars, appended %d chars", prependLen, appendLen)
	return text, result
}

// applyMask replaces the middle of regex-matched values with mask characters,
// preserving a configurable number of prefix and suffix characters.
func (e *TransformExecutor) applyMask(text string, rule TransformRule) (string, TransformResult) {
	result := TransformResult{
		RuleID:   rule.ID,
		RuleName: rule.Name,
		Type:     TransformMask,
	}

	visiblePrefix := rule.Config.VisiblePrefix
	if visiblePrefix <= 0 {
		visiblePrefix = 3
	}
	visibleSuffix := rule.Config.VisibleSuffix
	if visibleSuffix <= 0 {
		visibleSuffix = 4
	}
	maskChar := rule.Config.MaskChar
	if maskChar == "" {
		maskChar = "*"
	}

	totalMasked := 0
	for _, pattern := range rule.Config.MaskPatterns {
		re, err := e.getOrCompileRegex(pattern)
		if err != nil {
			e.logger.Warn("skipping invalid mask pattern", "pattern", pattern, "error", err)
			continue
		}

		text = re.ReplaceAllStringFunc(text, func(match string) string {
			totalMasked++
			runes := []rune(match)
			matchLen := len(runes)

			if matchLen <= visiblePrefix+visibleSuffix {
				// Match too short: mask the middle if any
				if matchLen <= 2 {
					return match // too short to mask meaningfully
				}
				prefix := string(runes[:1])
				suffixStr := string(runes[matchLen-1:])
				middle := strings.Repeat(maskChar, matchLen-2)
				return prefix + middle + suffixStr
			}

			prefix := string(runes[:visiblePrefix])
			suffixStr := string(runes[matchLen-visibleSuffix:])
			middleLen := matchLen - visiblePrefix - visibleSuffix
			middle := strings.Repeat(maskChar, middleLen)
			return prefix + middle + suffixStr
		})
	}

	result.Applied = totalMasked > 0
	result.Detail = fmt.Sprintf("%d values masked", totalMasked)
	return text, result
}

// IsBinaryContent returns true if the data appears to be binary content.
// It checks for null bytes in the first 512 bytes and common binary file
// signatures (PNG, JPEG, GIF, PDF, ZIP).
func IsBinaryContent(data []byte) bool {
	if len(data) == 0 {
		return false
	}

	// Check for common binary signatures
	signatures := [][]byte{
		{0x89, 'P', 'N', 'G'},       // PNG
		{0xFF, 0xD8, 0xFF},           // JPEG
		{'G', 'I', 'F', '8'},         // GIF
		{'%', 'P', 'D', 'F'},         // PDF
		{'P', 'K', 0x03, 0x04},       // ZIP/PK
	}

	for _, sig := range signatures {
		if len(data) >= len(sig) {
			match := true
			for i, b := range sig {
				if data[i] != b {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}

	// Check for null bytes in the first 512 bytes
	checkLen := 512
	if len(data) < checkLen {
		checkLen = len(data)
	}
	for i := 0; i < checkLen; i++ {
		if data[i] == 0 {
			return true
		}
	}

	return false
}
