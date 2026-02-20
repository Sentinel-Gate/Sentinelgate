package action

import (
	"regexp"
	"time"
)

// ScanMode controls how the response scanner handles detections.
type ScanMode string

const (
	// ScanModeMonitor logs detections without blocking responses.
	ScanModeMonitor ScanMode = "monitor"
	// ScanModeEnforce blocks responses containing prompt injection.
	ScanModeEnforce ScanMode = "enforce"
)

// ScanFinding represents a single pattern match found during scanning.
type ScanFinding struct {
	// PatternName is the identifier of the matched pattern (e.g., "system_prompt_override").
	PatternName string
	// PatternCategory groups related patterns (e.g., "prompt_injection", "delimiter_escape").
	PatternCategory string
	// MatchedText is the text that matched, truncated to 100 characters.
	MatchedText string
	// Position is the byte offset where the match starts in the scanned content.
	Position int
}

// ScanResult contains the outcome of scanning content for prompt injection.
type ScanResult struct {
	// Detected is true if one or more patterns matched.
	Detected bool
	// Findings contains all pattern matches found.
	Findings []ScanFinding
	// ScanDurationNs is how long the scan took in nanoseconds.
	ScanDurationNs int64
}

// compiledPattern holds a pre-compiled regex pattern with metadata.
type compiledPattern struct {
	name     string
	category string
	re       *regexp.Regexp
}

// ResponseScanner detects prompt injection patterns in MCP tool results.
// All patterns are compiled at construction time for minimal per-scan overhead.
type ResponseScanner struct {
	patterns []compiledPattern
}

// NewResponseScanner creates a ResponseScanner with compiled regex patterns
// for detecting prompt injection attacks in tool responses.
func NewResponseScanner() *ResponseScanner {
	rawPatterns := []struct {
		name     string
		category string
		pattern  string
	}{
		{
			name:     "system_prompt_override",
			category: "prompt_injection",
			pattern:  `(?i)(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts|rules|context)`,
		},
		{
			name:     "role_hijack",
			category: "prompt_injection",
			pattern:  `(?i)you\s+are\s+(?:now|actually|really)\s+(?:a|an|my)\s+`,
		},
		{
			name:     "instruction_injection",
			category: "prompt_injection",
			pattern:  `(?i)(?:new\s+instructions?|updated?\s+(?:instructions?|rules?|prompt)):\s*`,
		},
		{
			name:     "system_tag_injection",
			category: "prompt_injection",
			pattern:  `(?i)<\s*(?:system|assistant|user|human|ai)\s*>`,
		},
		{
			name:     "delimiter_escape",
			category: "delimiter_escape",
			pattern:  "(?i)(?:```|---|\\.{3})\\s*(?:system|instructions?|rules?)\\s*(?:```|---|\\.{3})",
		},
		{
			name:     "do_anything_now",
			category: "prompt_injection",
			pattern:  `(?i)(?:DAN|do\s+anything\s+now|jailbreak|ignore\s+safety)`,
		},
	}

	compiled := make([]compiledPattern, 0, len(rawPatterns))
	for _, rp := range rawPatterns {
		compiled = append(compiled, compiledPattern{
			name:     rp.name,
			category: rp.category,
			re:       regexp.MustCompile(rp.pattern),
		})
	}

	return &ResponseScanner{
		patterns: compiled,
	}
}

// Scan runs all compiled patterns against the given content string.
// Returns a ScanResult with any findings. Empty content returns immediately
// with no findings.
func (s *ResponseScanner) Scan(content string) ScanResult {
	start := time.Now()

	if content == "" {
		return ScanResult{
			ScanDurationNs: time.Since(start).Nanoseconds(),
		}
	}

	var findings []ScanFinding
	for _, p := range s.patterns {
		matches := p.re.FindAllStringIndex(content, -1)
		for _, loc := range matches {
			matchedText := content[loc[0]:loc[1]]
			if len(matchedText) > 100 {
				matchedText = matchedText[:100]
			}
			findings = append(findings, ScanFinding{
				PatternName:     p.name,
				PatternCategory: p.category,
				MatchedText:     matchedText,
				Position:        loc[0],
			})
		}
	}

	return ScanResult{
		Detected:       len(findings) > 0,
		Findings:       findings,
		ScanDurationNs: time.Since(start).Nanoseconds(),
	}
}

// ScanJSON recursively scans JSON-compatible values (strings, maps, slices)
// for prompt injection patterns. This handles the common case where MCP tool
// results are JSON objects with string fields that may contain injected content.
func (s *ResponseScanner) ScanJSON(v interface{}) ScanResult {
	start := time.Now()

	var findings []ScanFinding
	s.scanValue(v, &findings)

	return ScanResult{
		Detected:       len(findings) > 0,
		Findings:       findings,
		ScanDurationNs: time.Since(start).Nanoseconds(),
	}
}

// scanValue recursively extracts strings from JSON-compatible values and scans them.
func (s *ResponseScanner) scanValue(v interface{}, findings *[]ScanFinding) {
	switch val := v.(type) {
	case string:
		result := s.Scan(val)
		if result.Detected {
			*findings = append(*findings, result.Findings...)
		}
	case map[string]interface{}:
		for _, mapVal := range val {
			s.scanValue(mapVal, findings)
		}
	case []interface{}:
		for _, item := range val {
			s.scanValue(item, findings)
		}
		// Skip other types (numbers, bools, nil)
	}
}
