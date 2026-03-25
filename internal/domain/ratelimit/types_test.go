package ratelimit

import (
	"testing"
	"time"
)

func TestRateLimitConfig(t *testing.T) {
	cfg := RateLimitConfig{
		Rate:   100,
		Burst:  150,
		Period: time.Minute,
	}

	if cfg.Rate != 100 {
		t.Errorf("Rate = %d, want 100", cfg.Rate)
	}
	if cfg.Burst != 150 {
		t.Errorf("Burst = %d, want 150", cfg.Burst)
	}
	if cfg.Period != time.Minute {
		t.Errorf("Period = %v, want %v", cfg.Period, time.Minute)
	}
}

func TestRateLimitResult(t *testing.T) {
	result := RateLimitResult{
		Allowed:    true,
		Remaining:  42,
		RetryAfter: 0,
		ResetAfter: 30 * time.Second,
	}

	if !result.Allowed {
		t.Error("Allowed = false, want true")
	}
	if result.Remaining != 42 {
		t.Errorf("Remaining = %d, want 42", result.Remaining)
	}
	if result.RetryAfter != 0 {
		t.Errorf("RetryAfter = %v, want 0", result.RetryAfter)
	}
	if result.ResetAfter != 30*time.Second {
		t.Errorf("ResetAfter = %v, want %v", result.ResetAfter, 30*time.Second)
	}

	// Denied result
	denied := RateLimitResult{
		Allowed:    false,
		Remaining:  0,
		RetryAfter: 5 * time.Second,
		ResetAfter: 60 * time.Second,
	}

	if denied.Allowed {
		t.Error("Allowed = true, want false")
	}
	if denied.Remaining != 0 {
		t.Errorf("Remaining = %d, want 0", denied.Remaining)
	}
	if denied.RetryAfter != 5*time.Second {
		t.Errorf("RetryAfter = %v, want %v", denied.RetryAfter, 5*time.Second)
	}
}

func TestKeyGeneration_IP(t *testing.T) {
	key := FormatKey(KeyTypeIP, "192.168.1.1")
	expected := "ratelimit:ip:192.168.1.1"

	if key != expected {
		t.Errorf("FormatKey(KeyTypeIP, \"192.168.1.1\") = %q, want %q", key, expected)
	}
}

func TestKeyGeneration_User(t *testing.T) {
	key := FormatKey(KeyTypeUser, "user-123")
	expected := "ratelimit:user:user-123"

	if key != expected {
		t.Errorf("FormatKey(KeyTypeUser, \"user-123\") = %q, want %q", key, expected)
	}
}

func TestKeyTypeConstants(t *testing.T) {
	if KeyTypeIP != "ip" {
		t.Errorf("KeyTypeIP = %q, want %q", KeyTypeIP, "ip")
	}
	if KeyTypeUser != "user" {
		t.Errorf("KeyTypeUser = %q, want %q", KeyTypeUser, "user")
	}
}
