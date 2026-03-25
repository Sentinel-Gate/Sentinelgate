package action

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ContentPatternType identifies the kind of sensitive content detected.
type ContentPatternType string

const (
	PatternEmail    ContentPatternType = "email"
	PatternCCNumber ContentPatternType = "credit_card"
	PatternSSN      ContentPatternType = "us_ssn"
	PatternUKNI     ContentPatternType = "uk_ni_number"
	PatternPhone    ContentPatternType = "phone_number"
	PatternAWSKey   ContentPatternType = "aws_key"
	PatternGCPKey   ContentPatternType = "gcp_key"
	PatternAzureKey ContentPatternType = "azure_key"
	PatternStripe   ContentPatternType = "stripe_key"
	PatternGitHub   ContentPatternType = "github_token"
	PatternGeneric  ContentPatternType = "generic_secret"
)

// ContentPatternAction determines what to do when a pattern is detected.
type ContentPatternAction string

const (
	ContentActionBlock ContentPatternAction = "block"
	ContentActionMask  ContentPatternAction = "mask"
	ContentActionAlert ContentPatternAction = "alert"
)

// ContentFinding represents a single content scan detection.
type ContentFinding struct {
	PatternType ContentPatternType   `json:"pattern_type"`
	Action      ContentPatternAction `json:"action"`
	MatchedText string               `json:"matched_text"` // truncated/masked for safety
	Redacted    string               `json:"redacted"`     // placeholder used for masking
	Position    int                  `json:"position"`
	FieldPath   string               `json:"field_path"` // e.g. "arguments.content"
}

// ContentScanResult is the outcome of scanning arguments for sensitive content.
type ContentScanResult struct {
	Detected       bool             `json:"detected"`
	Findings       []ContentFinding `json:"findings"`
	ScanDurationNs int64            `json:"scan_duration_ns"`
	HasBlock       bool             `json:"has_block"` // at least one finding requires blocking
}

// contentPattern is a compiled pattern for sensitive content detection.
type contentPattern struct {
	patternType ContentPatternType
	re          *regexp.Regexp
	action      ContentPatternAction
	redactLabel string
	validate    func(match string) bool // optional secondary validation (e.g. Luhn)
}

// ContentScanner detects PII, secrets, and sensitive data in tool arguments.
// All patterns are pre-compiled at construction time.
type ContentScanner struct {
	mu       sync.RWMutex
	patterns []contentPattern
}

// NewContentScanner creates a ContentScanner with the default pattern set.
func NewContentScanner() *ContentScanner {
	patterns := []contentPattern{
		// PII patterns — default action: mask
		{
			patternType: PatternEmail,
			re:          regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`),
			action:      ContentActionMask,
			redactLabel: "[REDACTED-EMAIL]",
		},
		{
			patternType: PatternCCNumber,
			re:          regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`),
			action:      ContentActionMask,
			redactLabel: "[REDACTED-CC]",
			validate:    luhnCheck,
		},
		{
			patternType: PatternSSN,
			re:          regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			action:      ContentActionMask,
			redactLabel: "[REDACTED-SSN]",
			validate:    validateSSN,
		},
		{
			patternType: PatternUKNI,
			re:          regexp.MustCompile(`\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b`),
			action:      ContentActionMask,
			redactLabel: "[REDACTED-NINO]",
		},
		{
			patternType: PatternPhone,
			re:          regexp.MustCompile(`(?:\+\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{2,4}[-.\s]?\d{2,4}(?:[-.\s]?\d{2,4})?\b`),
			action:      ContentActionMask,
			redactLabel: "[REDACTED-PHONE]",
			validate:    validatePhone,
		},
		// Secret patterns — default action: block
		{
			patternType: PatternAWSKey,
			re:          regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`),
			action:      ContentActionBlock,
			redactLabel: "[REDACTED-AWS-KEY]",
		},
		{
			patternType: PatternGCPKey,
			re:          regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),
			action:      ContentActionBlock,
			redactLabel: "[REDACTED-GCP-KEY]",
		},
		{
			patternType: PatternAzureKey,
			re:          regexp.MustCompile(`\b[a-zA-Z0-9/+]{86}==\b`),
			action:      ContentActionBlock,
			redactLabel: "[REDACTED-AZURE-KEY]",
		},
		{
			patternType: PatternStripe,
			re:          regexp.MustCompile(`\b(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{24,}\b`),
			action:      ContentActionBlock,
			redactLabel: "[REDACTED-STRIPE-KEY]",
		},
		{
			patternType: PatternGitHub,
			re:          regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b`),
			action:      ContentActionBlock,
			redactLabel: "[REDACTED-GITHUB-TOKEN]",
		},
		{
			patternType: PatternGeneric,
			re:          regexp.MustCompile(`(?i)(?:password|passwd|pwd|secret|token|api_key|apikey|api-key)\s*[:=]\s*['"]?[^\s'"]{8,}['"]?`),
			action:      ContentActionBlock,
			redactLabel: "[REDACTED-SECRET]",
		},
	}

	return &ContentScanner{patterns: patterns}
}

// SetPatternAction changes the action for a specific pattern type.
// Valid actions: "off", "alert", "mask", "block".
// "off" disables the pattern entirely.
func (s *ContentScanner) SetPatternAction(patternType ContentPatternType, action ContentPatternAction) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.patterns {
		if s.patterns[i].patternType == patternType {
			s.patterns[i].action = action
			return
		}
	}
}

// GetPatternActions returns the current action for each pattern type.
func (s *ContentScanner) GetPatternActions() map[ContentPatternType]ContentPatternAction {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := make(map[ContentPatternType]ContentPatternAction, len(s.patterns))
	for _, p := range s.patterns {
		m[p.patternType] = p.action
	}
	return m
}

// ScanArguments scans a CanonicalAction's Arguments map for sensitive content.
// Returns a ContentScanResult with all findings.
func (s *ContentScanner) ScanArguments(args map[string]interface{}) ContentScanResult {
	start := time.Now()
	if len(args) == 0 {
		return ContentScanResult{ScanDurationNs: time.Since(start).Nanoseconds()}
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	var findings []ContentFinding
	s.scanMap(args, "arguments", &findings)

	hasBlock := false
	for _, f := range findings {
		if f.Action == ContentActionBlock {
			hasBlock = true
			break
		}
	}

	return ContentScanResult{
		Detected:       len(findings) > 0,
		Findings:       findings,
		ScanDurationNs: time.Since(start).Nanoseconds(),
		HasBlock:       hasBlock,
	}
}

// MaskArguments returns a deep copy of the arguments map with detected
// content replaced by redaction placeholders. Only patterns with action "mask"
// are replaced; "block" patterns cause the entire call to be rejected upstream.
func (s *ContentScanner) MaskArguments(args map[string]interface{}) map[string]interface{} {
	if len(args) == 0 {
		return args
	}
	// Deep copy via JSON round-trip.
	b, err := json.Marshal(args)
	if err != nil {
		return args
	}
	var copy map[string]interface{}
	if err := json.Unmarshal(b, &copy); err != nil {
		return args
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	s.maskMap(copy)
	return copy
}

// scanMap recursively scans a map for sensitive content.
func (s *ContentScanner) scanMap(m map[string]interface{}, prefix string, findings *[]ContentFinding) {
	for key, val := range m {
		path := prefix + "." + key
		s.scanValue(val, path, findings)
	}
}

// scanValue recursively scans a value.
func (s *ContentScanner) scanValue(v interface{}, path string, findings *[]ContentFinding) {
	switch val := v.(type) {
	case string:
		s.scanString(val, path, findings)
	case map[string]interface{}:
		s.scanMap(val, path, findings)
	case []interface{}:
		for i, item := range val {
			s.scanValue(item, path+"["+strconv.Itoa(i)+"]", findings)
		}
	}
}

// scanString runs all patterns against a single string.
func (s *ContentScanner) scanString(content, path string, findings *[]ContentFinding) {
	if content == "" {
		return
	}
	for _, p := range s.patterns {
		if p.action == "off" {
			continue
		}
		matches := p.re.FindAllStringIndex(content, -1)
		for _, loc := range matches {
			matched := content[loc[0]:loc[1]]
			if p.validate != nil && !p.validate(matched) {
				continue
			}
			displayText := matched
			if len(displayText) > 20 {
				displayText = displayText[:8] + "..." + displayText[len(displayText)-4:]
			}
			*findings = append(*findings, ContentFinding{
				PatternType: p.patternType,
				Action:      p.action,
				MatchedText: displayText,
				Redacted:    p.redactLabel,
				Position:    loc[0],
				FieldPath:   path,
			})
		}
	}
}

// maskMap recursively applies masking to all string values in a map.
func (s *ContentScanner) maskMap(m map[string]interface{}) {
	for key, val := range m {
		m[key] = s.maskValue(val)
	}
}

func (s *ContentScanner) maskValue(v interface{}) interface{} {
	switch val := v.(type) {
	case string:
		return s.maskString(val)
	case map[string]interface{}:
		s.maskMap(val)
		return val
	case []interface{}:
		for i, item := range val {
			val[i] = s.maskValue(item)
		}
		return val
	default:
		return v
	}
}

func (s *ContentScanner) maskString(content string) string {
	if content == "" {
		return content
	}
	result := content
	for _, p := range s.patterns {
		if p.action != ContentActionMask {
			continue
		}
		result = p.re.ReplaceAllStringFunc(result, func(match string) string {
			if p.validate != nil && !p.validate(match) {
				return match
			}
			return p.redactLabel
		})
	}
	return result
}

// luhnCheck validates a number string using the Luhn algorithm.
func luhnCheck(s string) bool {
	// Strip spaces and dashes.
	cleaned := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, s)
	if len(cleaned) < 13 || len(cleaned) > 19 {
		return false
	}
	sum := 0
	alt := false
	for i := len(cleaned) - 1; i >= 0; i-- {
		n := int(cleaned[i] - '0')
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

// validateSSN performs basic SSN validation (rejects known invalid ranges).
// L-39: Uses integer comparison for area range check instead of string comparison for clarity.
func validateSSN(s string) bool {
	parts := strings.Split(s, "-")
	if len(parts) != 3 {
		return false
	}
	area, err := strconv.Atoi(parts[0])
	if err != nil {
		return false
	}
	// Invalid area numbers.
	if area == 0 || area == 666 || (area >= 900 && area <= 999) {
		return false
	}
	return parts[1] != "00" && parts[2] != "0000"
}

// validatePhone checks that a phone number match has 7-15 digits (ITU-T E.164 range).
func validatePhone(s string) bool {
	cleaned := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, s)
	return len(cleaned) >= 7 && len(cleaned) <= 15
}
