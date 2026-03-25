package action

import (
	"strings"
	"testing"
)

func TestContentScanner_ScanArguments_Email(t *testing.T) {
	s := NewContentScanner()
	args := map[string]interface{}{
		"content": "Please send this to john@example.com and jane@test.org",
	}
	result := s.ScanArguments(args)
	if !result.Detected {
		t.Fatal("expected email detection")
	}
	if len(result.Findings) < 2 {
		t.Fatalf("expected at least 2 findings, got %d", len(result.Findings))
	}
	for _, f := range result.Findings {
		if f.PatternType != PatternEmail {
			t.Errorf("expected email pattern, got %s", f.PatternType)
		}
		if f.Action != ContentActionMask {
			t.Errorf("expected mask action for email, got %s", f.Action)
		}
	}
}

func TestContentScanner_ScanArguments_CreditCard(t *testing.T) {
	s := NewContentScanner()
	// Valid Luhn: 4111111111111111
	args := map[string]interface{}{
		"data": "My card is 4111111111111111 please process",
	}
	result := s.ScanArguments(args)
	if !result.Detected {
		t.Fatal("expected CC detection")
	}
	found := false
	for _, f := range result.Findings {
		if f.PatternType == PatternCCNumber {
			found = true
		}
	}
	if !found {
		t.Fatal("expected PatternCCNumber finding")
	}
}

func TestContentScanner_ScanArguments_CreditCard_InvalidLuhn(t *testing.T) {
	s := NewContentScanner()
	// Invalid Luhn number.
	args := map[string]interface{}{
		"data": "Number is 4111111111111112",
	}
	result := s.ScanArguments(args)
	for _, f := range result.Findings {
		if f.PatternType == PatternCCNumber {
			t.Fatal("should not detect invalid Luhn as credit card")
		}
	}
}

func TestContentScanner_ScanArguments_SSN(t *testing.T) {
	s := NewContentScanner()
	args := map[string]interface{}{
		"text": "SSN: 123-45-6789",
	}
	result := s.ScanArguments(args)
	if !result.Detected {
		t.Fatal("expected SSN detection")
	}
	found := false
	for _, f := range result.Findings {
		if f.PatternType == PatternSSN {
			found = true
		}
	}
	if !found {
		t.Fatal("expected PatternSSN finding")
	}
}

func TestContentScanner_ScanArguments_SSN_Invalid(t *testing.T) {
	s := NewContentScanner()
	// Invalid SSN: area 000 and 666 are invalid.
	args := map[string]interface{}{
		"text": "SSN: 000-45-6789",
	}
	result := s.ScanArguments(args)
	for _, f := range result.Findings {
		if f.PatternType == PatternSSN {
			t.Fatal("should not detect invalid SSN area 000")
		}
	}
}

func TestContentScanner_ScanArguments_AWSKey(t *testing.T) {
	s := NewContentScanner()
	args := map[string]interface{}{
		"config": "aws_key=AKIAIOSFODNN7EXAMPLE",
	}
	result := s.ScanArguments(args)
	if !result.Detected {
		t.Fatal("expected AWS key detection")
	}
	if !result.HasBlock {
		t.Fatal("expected block action for AWS key")
	}
}

func TestContentScanner_ScanArguments_GitHubToken(t *testing.T) {
	s := NewContentScanner()
	args := map[string]interface{}{
		"auth": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm",
	}
	result := s.ScanArguments(args)
	if !result.Detected {
		t.Fatal("expected GitHub token detection")
	}
	found := false
	for _, f := range result.Findings {
		if f.PatternType == PatternGitHub {
			found = true
		}
	}
	if !found {
		t.Fatal("expected PatternGitHub finding")
	}
}

func TestContentScanner_ScanArguments_GenericSecret(t *testing.T) {
	s := NewContentScanner()
	args := map[string]interface{}{
		"env": "password=MySecretPassword123!",
	}
	result := s.ScanArguments(args)
	if !result.Detected {
		t.Fatal("expected generic secret detection")
	}
	if !result.HasBlock {
		t.Fatal("expected block action for generic secret")
	}
}

func TestContentScanner_ScanArguments_NoMatch(t *testing.T) {
	s := NewContentScanner()
	args := map[string]interface{}{
		"path":    "/home/user/documents",
		"content": "Hello world, this is a normal text.",
	}
	result := s.ScanArguments(args)
	if result.Detected {
		t.Fatalf("expected no detection, got %d findings", len(result.Findings))
	}
}

func TestContentScanner_ScanArguments_Nested(t *testing.T) {
	s := NewContentScanner()
	args := map[string]interface{}{
		"data": map[string]interface{}{
			"user": map[string]interface{}{
				"email": "user@example.com",
			},
		},
	}
	result := s.ScanArguments(args)
	if !result.Detected {
		t.Fatal("expected detection in nested map")
	}
	if result.Findings[0].FieldPath != "arguments.data.user.email" {
		t.Errorf("expected field path arguments.data.user.email, got %s", result.Findings[0].FieldPath)
	}
}

func TestContentScanner_ScanArguments_Empty(t *testing.T) {
	s := NewContentScanner()
	result := s.ScanArguments(nil)
	if result.Detected {
		t.Fatal("expected no detection for nil args")
	}
}

func TestContentScanner_MaskArguments(t *testing.T) {
	s := NewContentScanner()
	args := map[string]interface{}{
		"content": "Send to john@example.com",
	}
	masked := s.MaskArguments(args)
	content, ok := masked["content"].(string)
	if !ok {
		t.Fatal("expected string content")
	}
	if content == "Send to john@example.com" {
		t.Fatal("expected email to be masked")
	}
	if content != "Send to [REDACTED-EMAIL]" {
		t.Errorf("expected 'Send to [REDACTED-EMAIL]', got %q", content)
	}
}

func TestContentScanner_UKNI(t *testing.T) {
	s := NewContentScanner()
	args := map[string]interface{}{
		"text": "NI number is AB 12 34 56 C",
	}
	result := s.ScanArguments(args)
	if !result.Detected {
		t.Fatal("expected UK NI number detection")
	}
	found := false
	for _, f := range result.Findings {
		if f.PatternType == PatternUKNI {
			found = true
		}
	}
	if !found {
		t.Fatal("expected PatternUKNI finding")
	}
}

func TestLuhnCheck(t *testing.T) {
	tests := []struct {
		input string
		valid bool
	}{
		{"4111111111111111", true},
		{"4111111111111112", false},
		{"5500000000000004", true},
		{"378282246310005", true},
		{"123", false},
	}
	for _, tt := range tests {
		if got := luhnCheck(tt.input); got != tt.valid {
			t.Errorf("luhnCheck(%q) = %v, want %v", tt.input, got, tt.valid)
		}
	}
}

func TestContentScanner_StripeKey(t *testing.T) {
	s := NewContentScanner()
	// Build test key at runtime to avoid GitHub push protection false positive.
	testKey := "sk_" + "live_1234567890abcdefghijklmn"
	args := map[string]interface{}{
		"key": testKey,
	}
	result := s.ScanArguments(args)
	if !result.Detected {
		t.Fatal("expected Stripe key detection")
	}
	found := false
	for _, f := range result.Findings {
		if f.PatternType == PatternStripe {
			found = true
		}
	}
	if !found {
		t.Fatal("expected PatternStripe finding")
	}
}

func TestContentScanner_RedactsPhoneNumbers(t *testing.T) {
	s := NewContentScanner()

	tests := []struct {
		name  string
		input string
	}{
		{"Swiss local", "Call me at 091 966 23 25 please"},
		{"Swiss international", "My number is +41 91 966 23 25"},
		{"US format", "Reach me at (555) 123-4567"},
		{"US dashes", "Phone: 555-123-4567"},
	}

	for _, tt := range tests {
		t.Run(tt.name+" detection", func(t *testing.T) {
			args := map[string]interface{}{"content": tt.input}
			result := s.ScanArguments(args)
			if !result.Detected {
				t.Fatalf("expected phone detection for %q", tt.input)
			}
			found := false
			for _, f := range result.Findings {
				if f.PatternType == PatternPhone {
					found = true
					if f.Action != ContentActionMask {
						t.Errorf("expected mask action for phone, got %s", f.Action)
					}
				}
			}
			if !found {
				t.Fatalf("expected PatternPhone finding for %q", tt.input)
			}
		})

		t.Run(tt.name+" masking", func(t *testing.T) {
			args := map[string]interface{}{"content": tt.input}
			masked := s.MaskArguments(args)
			content, ok := masked["content"].(string)
			if !ok {
				t.Fatal("expected string content")
			}
			if content == tt.input {
				t.Fatalf("expected phone to be masked in %q, got unchanged", tt.input)
			}
			if !strings.Contains(content, "[REDACTED-PHONE]") {
				t.Errorf("expected [REDACTED-PHONE] in result, got %q", content)
			}
		})
	}

	// Negative: short numbers should NOT match
	t.Run("short number not matched", func(t *testing.T) {
		args := map[string]interface{}{"content": "Code is 12 34"}
		result := s.ScanArguments(args)
		for _, f := range result.Findings {
			if f.PatternType == PatternPhone {
				t.Fatal("short number 12 34 should not be detected as phone")
			}
		}
	})
}

