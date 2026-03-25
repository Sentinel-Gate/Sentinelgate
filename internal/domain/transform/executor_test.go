package transform

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func newExecutor() *TransformExecutor {
	return NewTransformExecutor(nil)
}

func TestExecutor_Redact_SinglePattern(t *testing.T) {
	exec := newExecutor()
	text := "My API key is sk-abcdefghijklmnopqrstuvwx and it's secret"
	rules := []TransformRule{
		{
			ID: "r1", Name: "redact-api-key", Type: TransformRedact, Enabled: true,
			Priority: 10,
			Config:   TransformConfig{Patterns: []string{`sk-[a-zA-Z0-9]{20,}`}},
		},
	}

	result, results := exec.Apply(text, rules)
	if !strings.Contains(result, "[REDACTED]") {
		t.Errorf("expected [REDACTED] in result, got: %s", result)
	}
	if strings.Contains(result, "sk-abcdefghijklmnopqrstuvwx") {
		t.Error("API key should have been redacted")
	}
	if len(results) != 1 || !results[0].Applied {
		t.Error("expected 1 applied result")
	}
	if results[0].Detail != "1 matches redacted" {
		t.Errorf("unexpected detail: %s", results[0].Detail)
	}
}

func TestExecutor_Redact_MultiplePatterns(t *testing.T) {
	exec := newExecutor()
	text := "Key: sk-abc123def456ghi789jklmno, Email: user@example.com"
	rules := []TransformRule{
		{
			ID: "r1", Name: "multi-redact", Type: TransformRedact, Enabled: true,
			Priority: 10,
			Config: TransformConfig{Patterns: []string{
				`sk-[a-zA-Z0-9]{20,}`,
				`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
			}},
		},
	}

	result, results := exec.Apply(text, rules)
	if strings.Contains(result, "sk-") {
		t.Error("API key should have been redacted")
	}
	if strings.Contains(result, "user@example.com") {
		t.Error("email should have been redacted")
	}
	if !results[0].Applied {
		t.Error("expected applied=true")
	}
	if results[0].Detail != "2 matches redacted" {
		t.Errorf("unexpected detail: %s", results[0].Detail)
	}
}

func TestExecutor_Redact_NoMatch(t *testing.T) {
	exec := newExecutor()
	text := "No secrets here, just plain text."
	rules := []TransformRule{
		{
			ID: "r1", Name: "no-match", Type: TransformRedact, Enabled: true,
			Priority: 10,
			Config:   TransformConfig{Patterns: []string{`sk-[a-zA-Z0-9]{20,}`}},
		},
	}

	result, results := exec.Apply(text, rules)
	if result != text {
		t.Error("text should be unchanged when no match")
	}
	if results[0].Applied {
		t.Error("expected applied=false when no match")
	}
}

func TestExecutor_Redact_CustomReplacement(t *testing.T) {
	exec := newExecutor()
	text := "Token: sk-abcdefghijklmnopqrstuvwx"
	rules := []TransformRule{
		{
			ID: "r1", Name: "custom-replace", Type: TransformRedact, Enabled: true,
			Priority: 10,
			Config:   TransformConfig{Patterns: []string{`sk-[a-zA-Z0-9]{20,}`}, Replacement: "***REMOVED***"},
		},
	}

	result, _ := exec.Apply(text, rules)
	if !strings.Contains(result, "***REMOVED***") {
		t.Errorf("expected custom replacement, got: %s", result)
	}
	if strings.Contains(result, "[REDACTED]") {
		t.Error("should use custom replacement, not default")
	}
}

func TestExecutor_Truncate_ByBytes(t *testing.T) {
	exec := newExecutor()
	text := strings.Repeat("A", 200)
	rules := []TransformRule{
		{
			ID: "t1", Name: "byte-limit", Type: TransformTruncate, Enabled: true,
			Priority: 10,
			Config:   TransformConfig{MaxBytes: 50},
		},
	}

	result, results := exec.Apply(text, rules)
	// Result should be 50 bytes + default suffix
	if !strings.Contains(result, "... [truncated]") {
		t.Error("expected truncation suffix")
	}
	if len(result) > 50+len("\n... [truncated]")+5 {
		t.Errorf("result too long: %d chars", len(result))
	}
	if !results[0].Applied {
		t.Error("expected applied=true")
	}
}

func TestExecutor_Truncate_ByLines(t *testing.T) {
	exec := newExecutor()
	lines := make([]string, 20)
	for i := range lines {
		lines[i] = "line content"
	}
	text := strings.Join(lines, "\n")

	rules := []TransformRule{
		{
			ID: "t1", Name: "line-limit", Type: TransformTruncate, Enabled: true,
			Priority: 10,
			Config:   TransformConfig{MaxLines: 5},
		},
	}

	result, results := exec.Apply(text, rules)
	resultLines := strings.Split(result, "\n")
	// First 5 lines + suffix adds at most 2 more lines
	if len(resultLines) > 7 {
		t.Errorf("expected ~5 lines + suffix, got %d lines", len(resultLines))
	}
	if !results[0].Applied {
		t.Error("expected applied=true")
	}
}

func TestExecutor_Truncate_BothLimits(t *testing.T) {
	exec := newExecutor()
	// 100 lines of 20 chars each = 2100 bytes with newlines
	lines := make([]string, 100)
	for i := range lines {
		lines[i] = strings.Repeat("X", 20)
	}
	text := strings.Join(lines, "\n")

	rules := []TransformRule{
		{
			ID: "t1", Name: "both-limits", Type: TransformTruncate, Enabled: true,
			Priority: 10,
			Config:   TransformConfig{MaxBytes: 500, MaxLines: 10},
		},
	}

	result, results := exec.Apply(text, rules)
	if !strings.Contains(result, "... [truncated]") {
		t.Error("expected truncation suffix")
	}
	if !results[0].Applied {
		t.Error("expected applied=true")
	}
}

func TestExecutor_Truncate_UnderLimit(t *testing.T) {
	exec := newExecutor()
	text := "Short text"
	rules := []TransformRule{
		{
			ID: "t1", Name: "no-truncate", Type: TransformTruncate, Enabled: true,
			Priority: 10,
			Config:   TransformConfig{MaxBytes: 1000, MaxLines: 100},
		},
	}

	result, results := exec.Apply(text, rules)
	if result != text {
		t.Error("text should be unchanged when under limits")
	}
	if results[0].Applied {
		t.Error("expected applied=false when under limits")
	}
}

func TestExecutor_Inject_Prepend(t *testing.T) {
	exec := newExecutor()
	text := "Original response"
	rules := []TransformRule{
		{
			ID: "i1", Name: "prepend-warning", Type: TransformInject, Enabled: true,
			Priority: 10,
			Config:   TransformConfig{Prepend: "[WARNING] Test environment"},
		},
	}

	result, results := exec.Apply(text, rules)
	if !strings.HasPrefix(result, "[WARNING] Test environment\n") {
		t.Errorf("expected prepended text, got: %s", result)
	}
	if !strings.Contains(result, "Original response") {
		t.Error("original text should be preserved")
	}
	if !results[0].Applied {
		t.Error("expected applied=true")
	}
}

func TestExecutor_Inject_Append(t *testing.T) {
	exec := newExecutor()
	text := "Original response"
	rules := []TransformRule{
		{
			ID: "i1", Name: "append-footer", Type: TransformInject, Enabled: true,
			Priority: 10,
			Config:   TransformConfig{Append: "--- end ---"},
		},
	}

	result, results := exec.Apply(text, rules)
	if !strings.HasSuffix(result, "\n--- end ---") {
		t.Errorf("expected appended text, got: %s", result)
	}
	if !strings.HasPrefix(result, "Original response") {
		t.Error("original text should be at the start")
	}
	if !results[0].Applied {
		t.Error("expected applied=true")
	}
}

func TestExecutor_Inject_Both(t *testing.T) {
	exec := newExecutor()
	text := "Original response"
	rules := []TransformRule{
		{
			ID: "i1", Name: "inject-both", Type: TransformInject, Enabled: true,
			Priority: 10,
			Config:   TransformConfig{Prepend: "HEADER", Append: "FOOTER"},
		},
	}

	result, results := exec.Apply(text, rules)
	if !strings.HasPrefix(result, "HEADER\n") {
		t.Errorf("expected HEADER prefix, got: %s", result)
	}
	if !strings.HasSuffix(result, "\nFOOTER") {
		t.Errorf("expected FOOTER suffix, got: %s", result)
	}
	if !strings.Contains(result, "Original response") {
		t.Error("original text should be in the middle")
	}
	if !results[0].Applied {
		t.Error("expected applied=true")
	}
	if results[0].Detail != "prepended 6 chars, appended 6 chars" {
		t.Errorf("unexpected detail: %s", results[0].Detail)
	}
}

func TestExecutor_Mask_APIKey(t *testing.T) {
	exec := newExecutor()
	text := "The key is sk-abcdefghijklmnop and use it carefully"
	rules := []TransformRule{
		{
			ID: "m1", Name: "mask-key", Type: TransformMask, Enabled: true,
			Priority: 10,
			Config:   TransformConfig{MaskPatterns: []string{`sk-[a-zA-Z0-9]+`}},
		},
	}

	result, results := exec.Apply(text, rules)
	// The match is "sk-abcdefghijklmnop" (19 chars)
	// Default: prefix 3 chars "sk-", suffix 4 chars "mnop", middle 12 chars masked
	if strings.Contains(result, "sk-abcdefghijklmnop") {
		t.Error("original key should be masked")
	}
	if !strings.Contains(result, "sk-") {
		t.Error("prefix should be preserved")
	}
	if !strings.Contains(result, "mnop") {
		t.Error("suffix should be preserved")
	}
	if !strings.Contains(result, "****") {
		t.Error("middle should contain mask characters")
	}
	if !results[0].Applied {
		t.Error("expected applied=true")
	}
	if results[0].Detail != "1 values masked" {
		t.Errorf("unexpected detail: %s", results[0].Detail)
	}
}

func TestExecutor_Mask_ShortMatch(t *testing.T) {
	exec := newExecutor()
	// Match "abc" (3 chars) - shorter than default prefix(3)+suffix(4)=7
	text := "short value: abc here"
	rules := []TransformRule{
		{
			ID: "m1", Name: "mask-short", Type: TransformMask, Enabled: true,
			Priority: 10,
			Config:   TransformConfig{MaskPatterns: []string{`abc`}},
		},
	}

	result, results := exec.Apply(text, rules)
	// 3 chars: too short for prefix+suffix, so mask middle only: a*c
	if !strings.Contains(result, "a*c") {
		t.Errorf("expected a*c for short match, got: %s", result)
	}
	if !results[0].Applied {
		t.Error("expected applied=true")
	}
}

func TestExecutor_Mask_CustomChar(t *testing.T) {
	exec := newExecutor()
	text := "Token: sk-abcdefghijklmnop"
	rules := []TransformRule{
		{
			ID: "m1", Name: "mask-custom", Type: TransformMask, Enabled: true,
			Priority: 10,
			Config: TransformConfig{
				MaskPatterns: []string{`sk-[a-zA-Z0-9]+`},
				MaskChar:     "X",
			},
		},
	}

	result, _ := exec.Apply(text, rules)
	if !strings.Contains(result, "XXX") {
		t.Errorf("expected custom mask char X, got: %s", result)
	}
	if strings.Contains(result, "***") {
		t.Error("should use custom char X, not default *")
	}
}

func TestExecutor_DryRun_SkippedInApply(t *testing.T) {
	exec := newExecutor()
	text := "Original response"
	rules := []TransformRule{
		{
			ID: "d1", Name: "dry-run", Type: TransformDryRun, Enabled: true,
			Priority: 10,
			Config:   TransformConfig{Response: `{"success": true, "dry_run": true}`},
		},
	}

	result, results := exec.Apply(text, rules)
	if result != text {
		t.Error("dry-run should not modify text in Apply")
	}
	if len(results) != 1 {
		t.Fatal("expected 1 result")
	}
	if results[0].Applied {
		t.Error("expected applied=false for dry-run")
	}
	if results[0].Detail != "dry-run handled at pipeline level" {
		t.Errorf("unexpected detail: %s", results[0].Detail)
	}
}

func TestExecutor_MultipleRules_PriorityOrder(t *testing.T) {
	exec := newExecutor()
	text := "API key: sk-abcdefghijklmnopqrstuvwx is here"
	rules := []TransformRule{
		{
			ID: "inject1", Name: "inject-footer", Type: TransformInject, Enabled: true,
			Priority: 20,
			Config:   TransformConfig{Append: "[FILTERED]"},
		},
		{
			ID: "redact1", Name: "redact-key", Type: TransformRedact, Enabled: true,
			Priority: 10,
			Config:   TransformConfig{Patterns: []string{`sk-[a-zA-Z0-9]{20,}`}},
		},
	}

	result, results := exec.Apply(text, rules)

	// Inject (priority 20) runs first (higher priority = applied first)
	if results[0].RuleName != "inject-footer" {
		t.Errorf("expected inject first, got: %s", results[0].RuleName)
	}
	// Redact (priority 10) runs second
	if results[1].RuleName != "redact-key" {
		t.Errorf("expected redact second, got: %s", results[1].RuleName)
	}

	// Verify both applied
	if !strings.Contains(result, "[REDACTED]") {
		t.Error("redact should have been applied")
	}
	if !strings.HasSuffix(result, "\n[FILTERED]") {
		t.Error("inject should have been applied")
	}
}

func TestExecutor_DisabledRule_Skipped(t *testing.T) {
	exec := newExecutor()
	text := "API key: sk-abcdefghijklmnopqrstuvwx"
	rules := []TransformRule{
		{
			ID: "r1", Name: "disabled-redact", Type: TransformRedact, Enabled: false,
			Priority: 10,
			Config:   TransformConfig{Patterns: []string{`sk-[a-zA-Z0-9]{20,}`}},
		},
	}

	result, results := exec.Apply(text, rules)
	if result != text {
		t.Error("disabled rule should not modify text")
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results for disabled rule, got %d", len(results))
	}
}

func TestIsBinaryContent_PNG(t *testing.T) {
	data := []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}
	if !IsBinaryContent(data) {
		t.Error("expected PNG to be detected as binary")
	}
}

func TestIsBinaryContent_JPEG(t *testing.T) {
	data := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10}
	if !IsBinaryContent(data) {
		t.Error("expected JPEG to be detected as binary")
	}
}

func TestIsBinaryContent_NullBytes(t *testing.T) {
	data := []byte("Hello\x00World")
	if !IsBinaryContent(data) {
		t.Error("expected null bytes to be detected as binary")
	}
}

func TestIsBinaryContent_TextContent(t *testing.T) {
	data := []byte("This is plain text content with no binary characters.\nJust normal text.")
	if IsBinaryContent(data) {
		t.Error("expected plain text to not be detected as binary")
	}
}

func TestIsBinaryContent_Empty(t *testing.T) {
	if IsBinaryContent(nil) {
		t.Error("nil data should not be detected as binary")
	}
	if IsBinaryContent([]byte{}) {
		t.Error("empty data should not be detected as binary")
	}
}

// TestApplyTruncate_UTF8 verifies that byte-limit truncation respects UTF-8 rune
// boundaries, never producing invalid UTF-8 sequences.
func TestApplyTruncate_UTF8(t *testing.T) {
	exec := newExecutor()

	// "Hello " is 6 bytes, then Chinese chars are 3 bytes each:
	// 你 = 3 bytes (E4 BD A0), 好 = 3 bytes (E5 A5 BD), etc.
	text := "Hello 你好世界 emoji 🎉!"
	// "Hello " = 6 bytes, 你 = 3, 好 = 3, 世 = 3, 界 = 3 = 18 bytes for "Hello 你好世界"

	tests := []struct {
		name     string
		maxBytes int
	}{
		{"cut inside first Chinese char", 8},  // between "Hello " (6) and 你 (6+3=9)
		{"cut inside second Chinese char", 10}, // between 你 (9) and 好 (9+3=12)
		{"exact rune boundary", 9},             // exactly after 你
		{"cut inside emoji", 25},               // emoji 🎉 is 4 bytes
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rules := []TransformRule{
				{
					ID: "t1", Name: "utf8-truncate", Type: TransformTruncate, Enabled: true,
					Priority: 10,
					Config:   TransformConfig{MaxBytes: tc.maxBytes, Suffix: "..."},
				},
			}

			result, results := exec.Apply(text, rules)

			if !utf8.ValidString(result) {
				t.Errorf("result is not valid UTF-8: %q", result)
			}
			if !results[0].Applied {
				t.Error("expected applied=true")
			}
			// The truncated part (before suffix) should be <= MaxBytes
			truncatedPart := strings.TrimSuffix(result, "...")
			if len(truncatedPart) > tc.maxBytes {
				t.Errorf("truncated part is %d bytes, expected <= %d", len(truncatedPart), tc.maxBytes)
			}
		})
	}
}

// TestApplyTruncate_UTF8_Emoji tests truncation with 4-byte emoji characters.
func TestApplyTruncate_UTF8_Emoji(t *testing.T) {
	exec := newExecutor()
	// "abc" = 3 bytes, 🎉 = 4 bytes (F0 9F 8E 89), "def" = 3 bytes
	text := "abc🎉def🎄ghi"

	rules := []TransformRule{
		{
			ID: "t1", Name: "emoji-truncate", Type: TransformTruncate, Enabled: true,
			Priority: 10,
			Config:   TransformConfig{MaxBytes: 5, Suffix: "..."},
		},
	}

	result, results := exec.Apply(text, rules)

	if !utf8.ValidString(result) {
		t.Errorf("result is not valid UTF-8: %q", result)
	}
	if !results[0].Applied {
		t.Error("expected applied=true")
	}
	// MaxBytes=5 cuts inside the emoji after "abc" (3 bytes).
	// The emoji starts at byte 3 and ends at byte 7.
	// So truncation should back up to byte 3 (after "abc").
	truncatedPart := strings.TrimSuffix(result, "...")
	if !strings.HasPrefix(truncatedPart, "abc") {
		t.Errorf("expected truncated part to start with 'abc', got: %q", truncatedPart)
	}
	if len(truncatedPart) > 5 {
		t.Errorf("truncated part is %d bytes, expected <= 5", len(truncatedPart))
	}
}

// TestApplyTruncate_UTF8_OnlyASCII verifies that ASCII-only text is truncated
// at the exact byte boundary (no rune boundary adjustment needed).
func TestApplyTruncate_UTF8_OnlyASCII(t *testing.T) {
	exec := newExecutor()
	text := strings.Repeat("A", 100)

	rules := []TransformRule{
		{
			ID: "t1", Name: "ascii-truncate", Type: TransformTruncate, Enabled: true,
			Priority: 10,
			Config:   TransformConfig{MaxBytes: 50, Suffix: "..."},
		},
	}

	result, _ := exec.Apply(text, rules)
	truncatedPart := strings.TrimSuffix(result, "...")
	if len(truncatedPart) != 50 {
		t.Errorf("expected exactly 50 bytes, got %d", len(truncatedPart))
	}
}

// TestApplyRedact_CachesRegex verifies that the regex cache works correctly
// by applying the same pattern multiple times without error.
func TestApplyRedact_CachesRegex(t *testing.T) {
	exec := newExecutor()
	pattern := `\b\d{3}-\d{2}-\d{4}\b` // SSN pattern

	rules := []TransformRule{
		{
			ID: "r1", Name: "redact-ssn", Type: TransformRedact, Enabled: true,
			Priority: 10,
			Config:   TransformConfig{Patterns: []string{pattern}},
		},
	}

	// First call -- compiles and caches the regex
	text1 := "SSN: 123-45-6789 is private"
	result1, results1 := exec.Apply(text1, rules)
	if !results1[0].Applied {
		t.Error("first call: expected applied=true")
	}
	if strings.Contains(result1, "123-45-6789") {
		t.Error("first call: SSN should have been redacted")
	}

	// Second call -- uses cached regex
	text2 := "Another SSN: 987-65-4321 here"
	result2, results2 := exec.Apply(text2, rules)
	if !results2[0].Applied {
		t.Error("second call: expected applied=true")
	}
	if strings.Contains(result2, "987-65-4321") {
		t.Error("second call: SSN should have been redacted")
	}

	// Verify cache has the pattern
	exec.cacheMu.RLock()
	_, cached := exec.regexCache[pattern]
	exec.cacheMu.RUnlock()
	if !cached {
		t.Error("pattern should be in the regex cache after first use")
	}
}

// TestApplyMask_CachesRegex verifies that mask also uses the regex cache.
func TestApplyMask_CachesRegex(t *testing.T) {
	exec := newExecutor()
	pattern := `sk-[a-zA-Z0-9]+`

	rules := []TransformRule{
		{
			ID: "m1", Name: "mask-key", Type: TransformMask, Enabled: true,
			Priority: 10,
			Config:   TransformConfig{MaskPatterns: []string{pattern}},
		},
	}

	// First call
	text1 := "Key: sk-abcdefghijklmnop"
	_, _ = exec.Apply(text1, rules)

	// Second call
	text2 := "Key: sk-zyxwvutsrqponmlk"
	_, _ = exec.Apply(text2, rules)

	// Verify cache
	exec.cacheMu.RLock()
	_, cached := exec.regexCache[pattern]
	exec.cacheMu.RUnlock()
	if !cached {
		t.Error("mask pattern should be in the regex cache")
	}
}
