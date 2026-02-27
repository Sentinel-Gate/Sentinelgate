package action

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// outboundMockNext records whether it was called and returns the action.
type outboundMockNext struct {
	called atomic.Bool
}

func (m *outboundMockNext) Intercept(_ context.Context, a *CanonicalAction) (*CanonicalAction, error) {
	m.called.Store(true)
	return a, nil
}

// newTestResolver creates a DNSResolver with a mock lookup function.
func newTestResolver(lookupMap map[string][]string) *DNSResolver {
	return NewDNSResolver(slog.Default(), WithLookupFunc(func(host string) ([]string, error) {
		ips, ok := lookupMap[host]
		if !ok {
			return nil, errors.New("dns: host not found")
		}
		return ips, nil
	}))
}

func TestOutboundPassthroughNoURLs(t *testing.T) {
	resolver := newTestResolver(nil)
	next := &outboundMockNext{}
	interceptor := NewOutboundInterceptor(nil, resolver, next, slog.Default())

	a := &CanonicalAction{
		RequestID: "req-1",
		Arguments: map[string]interface{}{"count": 42},
	}

	result, err := interceptor.Intercept(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !next.called.Load() {
		t.Fatal("expected next interceptor to be called")
	}
}

func TestOutboundBlockOnBlocklistMatch(t *testing.T) {
	resolver := newTestResolver(map[string][]string{
		"foo.ngrok.io": {"1.2.3.4"},
	})
	next := &outboundMockNext{}

	rules := []OutboundRule{
		{
			ID:       "test-block-1",
			Name:     "Block ngrok",
			Mode:     RuleModeBlocklist,
			Enabled:  true,
			Priority: 100,
			Targets: []OutboundTarget{
				{Type: TargetDomainGlob, Value: "*.ngrok.io"},
			},
			HelpText: "ngrok is blocked",
			HelpURL:  "/admin/#/security/outbound",
		},
	}

	interceptor := NewOutboundInterceptor(rules, resolver, next, slog.Default())

	a := &CanonicalAction{
		RequestID: "req-2",
		Arguments: map[string]interface{}{"url": "https://foo.ngrok.io/exfil"},
	}

	_, err := interceptor.Intercept(context.Background(), a)
	if err == nil {
		t.Fatal("expected error for blocked destination")
	}
	if next.called.Load() {
		t.Fatal("next interceptor should NOT have been called")
	}

	// Verify it's an OutboundDenyError
	var denyErr *OutboundDenyError
	if !errors.As(err, &denyErr) {
		t.Fatalf("expected OutboundDenyError, got %T: %v", err, err)
	}
	if denyErr.RuleName != "Block ngrok" {
		t.Errorf("expected rule name 'Block ngrok', got %q", denyErr.RuleName)
	}
}

func TestOutboundAllowOnBlocklistNonMatch(t *testing.T) {
	resolver := newTestResolver(map[string][]string{
		"github.com": {"140.82.121.4"},
	})
	next := &outboundMockNext{}

	rules := []OutboundRule{
		{
			ID:       "test-block-1",
			Name:     "Block ngrok",
			Mode:     RuleModeBlocklist,
			Enabled:  true,
			Priority: 100,
			Targets: []OutboundTarget{
				{Type: TargetDomainGlob, Value: "*.ngrok.io"},
			},
		},
	}

	interceptor := NewOutboundInterceptor(rules, resolver, next, slog.Default())

	a := &CanonicalAction{
		RequestID: "req-3",
		Arguments: map[string]interface{}{"url": "https://github.com/repo"},
	}

	result, err := interceptor.Intercept(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !next.called.Load() {
		t.Fatal("expected next interceptor to be called")
	}
}

func TestOutboundAllowlistBlocksNonMatching(t *testing.T) {
	resolver := newTestResolver(map[string][]string{
		"evil.com": {"6.6.6.6"},
	})
	next := &outboundMockNext{}

	rules := []OutboundRule{
		{
			ID:       "allowlist-1",
			Name:     "Allow only api.example.com",
			Mode:     RuleModeAllowlist,
			Enabled:  true,
			Priority: 100,
			Targets: []OutboundTarget{
				{Type: TargetDomain, Value: "api.example.com"},
			},
			HelpText: "Only api.example.com is allowed",
		},
	}

	interceptor := NewOutboundInterceptor(rules, resolver, next, slog.Default())

	a := &CanonicalAction{
		RequestID: "req-4",
		Arguments: map[string]interface{}{"url": "https://evil.com/steal"},
	}

	_, err := interceptor.Intercept(context.Background(), a)
	if err == nil {
		t.Fatal("expected error for non-matching allowlist destination")
	}
	if next.called.Load() {
		t.Fatal("next interceptor should NOT have been called")
	}

	var denyErr *OutboundDenyError
	if !errors.As(err, &denyErr) {
		t.Fatalf("expected OutboundDenyError, got %T: %v", err, err)
	}
}

func TestOutboundAllowlistAllowsMatching(t *testing.T) {
	resolver := newTestResolver(map[string][]string{
		"api.example.com": {"10.0.0.1"},
	})
	next := &outboundMockNext{}

	rules := []OutboundRule{
		{
			ID:       "allowlist-1",
			Name:     "Allow only api.example.com",
			Mode:     RuleModeAllowlist,
			Enabled:  true,
			Priority: 100,
			Targets: []OutboundTarget{
				{Type: TargetDomain, Value: "api.example.com"},
			},
		},
	}

	interceptor := NewOutboundInterceptor(rules, resolver, next, slog.Default())

	a := &CanonicalAction{
		RequestID: "req-5",
		Arguments: map[string]interface{}{"url": "https://api.example.com/data"},
	}

	result, err := interceptor.Intercept(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !next.called.Load() {
		t.Fatal("expected next interceptor to be called")
	}
}

func TestOutboundDestinationPopulatedForCEL(t *testing.T) {
	resolver := newTestResolver(map[string][]string{
		"api.example.com": {"93.184.216.34"},
	})
	next := &outboundMockNext{}

	// No blocking rules - just pass through so we can check Destination.
	interceptor := NewOutboundInterceptor(nil, resolver, next, slog.Default())

	a := &CanonicalAction{
		RequestID: "req-6",
		Arguments: map[string]interface{}{"url": "https://api.example.com:8443/v1/data"},
	}

	result, err := interceptor.Intercept(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Destination.Domain != "api.example.com" {
		t.Errorf("expected domain 'api.example.com', got %q", result.Destination.Domain)
	}
	if result.Destination.IP != "93.184.216.34" {
		t.Errorf("expected IP '93.184.216.34', got %q", result.Destination.IP)
	}
	if result.Destination.Port != 8443 {
		t.Errorf("expected port 8443, got %d", result.Destination.Port)
	}
	if result.Destination.Scheme != "https" {
		t.Errorf("expected scheme 'https', got %q", result.Destination.Scheme)
	}
	if result.Destination.URL != "https://api.example.com:8443/v1/data" {
		t.Errorf("expected URL 'https://api.example.com:8443/v1/data', got %q", result.Destination.URL)
	}
	if result.Destination.Path != "/v1/data" {
		t.Errorf("expected path '/v1/data', got %q", result.Destination.Path)
	}
}

func TestOutboundDNSResolutionCalled(t *testing.T) {
	var resolvedDomain string
	resolver := NewDNSResolver(slog.Default(), WithLookupFunc(func(host string) ([]string, error) {
		resolvedDomain = host
		return []string{"1.2.3.4"}, nil
	}))
	next := &outboundMockNext{}

	interceptor := NewOutboundInterceptor(nil, resolver, next, slog.Default())

	a := &CanonicalAction{
		RequestID: "req-7",
		Arguments: map[string]interface{}{"url": "https://example.org/path"},
	}

	_, err := interceptor.Intercept(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resolvedDomain != "example.org" {
		t.Errorf("expected DNS resolution for 'example.org', got %q", resolvedDomain)
	}
}

func TestOutboundRequestPinsReleased(t *testing.T) {
	resolver := newTestResolver(map[string][]string{
		"example.com": {"1.2.3.4"},
	})
	next := &outboundMockNext{}

	interceptor := NewOutboundInterceptor(nil, resolver, next, slog.Default())

	a := &CanonicalAction{
		RequestID: "req-8-release",
		Arguments: map[string]interface{}{"url": "https://example.com/test"},
	}

	_, err := interceptor.Intercept(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify pins were released by checking the resolver's internal state.
	resolver.mu.RLock()
	_, hasPins := resolver.requestPins["req-8-release"]
	resolver.mu.RUnlock()

	if hasPins {
		t.Error("expected request pins to be released after intercept completes")
	}
}

func TestOutboundDenyMessageIncludesRuleInfo(t *testing.T) {
	resolver := newTestResolver(map[string][]string{
		"evil.ngrok.io": {"1.2.3.4"},
	})
	next := &outboundMockNext{}

	rules := []OutboundRule{
		{
			ID:       "info-rule",
			Name:     "Block Evil Tunnels",
			Mode:     RuleModeBlocklist,
			Enabled:  true,
			Priority: 100,
			Targets: []OutboundTarget{
				{Type: TargetDomainGlob, Value: "*.ngrok.io"},
			},
			HelpText: "Tunneling services are blocked for security",
			HelpURL:  "https://docs.example.com/security/outbound",
		},
	}

	interceptor := NewOutboundInterceptor(rules, resolver, next, slog.Default())

	a := &CanonicalAction{
		RequestID: "req-9",
		Arguments: map[string]interface{}{"url": "https://evil.ngrok.io/data"},
	}

	_, err := interceptor.Intercept(context.Background(), a)
	if err == nil {
		t.Fatal("expected error")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "Block Evil Tunnels") {
		t.Errorf("error should contain rule name, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "Tunneling services are blocked for security") {
		t.Errorf("error should contain help text, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "https://docs.example.com/security/outbound") {
		t.Errorf("error should contain help URL, got: %s", errMsg)
	}
}

func TestOutboundMultipleURLsFirstBlockedStops(t *testing.T) {
	resolver := newTestResolver(map[string][]string{
		"evil.ngrok.io":    {"1.2.3.4"},
		"good.example.com": {"5.6.7.8"},
	})
	next := &outboundMockNext{}

	rules := []OutboundRule{
		{
			ID:       "block-ngrok",
			Name:     "Block ngrok",
			Mode:     RuleModeBlocklist,
			Enabled:  true,
			Priority: 100,
			Targets: []OutboundTarget{
				{Type: TargetDomainGlob, Value: "*.ngrok.io"},
			},
		},
	}

	interceptor := NewOutboundInterceptor(rules, resolver, next, slog.Default())

	a := &CanonicalAction{
		RequestID: "req-10",
		Arguments: map[string]interface{}{
			"url1": "https://evil.ngrok.io/exfil",
			"url2": "https://good.example.com/ok",
		},
	}

	_, err := interceptor.Intercept(context.Background(), a)
	if err == nil {
		t.Fatal("expected error for blocked URL")
	}
	if next.called.Load() {
		t.Fatal("next interceptor should NOT have been called when first URL is blocked")
	}
}

func TestOutboundRulesEvaluatedInPriorityOrder(t *testing.T) {
	resolver := newTestResolver(map[string][]string{
		"target.example.com": {"1.2.3.4"},
	})
	next := &outboundMockNext{}

	rules := []OutboundRule{
		{
			ID:       "low-priority",
			Name:     "Low Priority Rule",
			Mode:     RuleModeBlocklist,
			Enabled:  true,
			Priority: 200, // Higher number = lower priority
			Targets: []OutboundTarget{
				{Type: TargetDomain, Value: "target.example.com"},
			},
			HelpText: "Low priority",
		},
		{
			ID:       "high-priority",
			Name:     "High Priority Rule",
			Mode:     RuleModeBlocklist,
			Enabled:  true,
			Priority: 50, // Lower number = higher priority
			Targets: []OutboundTarget{
				{Type: TargetDomain, Value: "target.example.com"},
			},
			HelpText: "High priority",
		},
	}

	interceptor := NewOutboundInterceptor(rules, resolver, next, slog.Default())

	a := &CanonicalAction{
		RequestID: "req-11",
		Arguments: map[string]interface{}{"url": "https://target.example.com/test"},
	}

	_, err := interceptor.Intercept(context.Background(), a)
	if err == nil {
		t.Fatal("expected error")
	}

	var denyErr *OutboundDenyError
	if !errors.As(err, &denyErr) {
		t.Fatalf("expected OutboundDenyError, got %T: %v", err, err)
	}
	if denyErr.RuleName != "High Priority Rule" {
		t.Errorf("expected 'High Priority Rule' (priority 50) to win, got %q", denyErr.RuleName)
	}
}

func TestOutboundDisabledRulesSkipped(t *testing.T) {
	resolver := newTestResolver(map[string][]string{
		"target.example.com": {"1.2.3.4"},
	})
	next := &outboundMockNext{}

	rules := []OutboundRule{
		{
			ID:       "disabled-rule",
			Name:     "Disabled Block",
			Mode:     RuleModeBlocklist,
			Enabled:  false, // Disabled!
			Priority: 100,
			Targets: []OutboundTarget{
				{Type: TargetDomain, Value: "target.example.com"},
			},
		},
	}

	interceptor := NewOutboundInterceptor(rules, resolver, next, slog.Default())

	a := &CanonicalAction{
		RequestID: "req-12",
		Arguments: map[string]interface{}{"url": "https://target.example.com/data"},
	}

	result, err := interceptor.Intercept(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v (disabled rule should not block)", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !next.called.Load() {
		t.Fatal("expected next interceptor to be called (disabled rule)")
	}
}

func TestOutboundErrorUnwrapsToSentinel(t *testing.T) {
	resolver := newTestResolver(map[string][]string{
		"evil.ngrok.io": {"1.2.3.4"},
	})
	next := &outboundMockNext{}

	rules := DefaultBlocklistRules()
	for i := range rules {
		rules[i].Enabled = true
	}
	interceptor := NewOutboundInterceptor(rules, resolver, next, slog.Default())

	a := &CanonicalAction{
		RequestID: "req-13",
		Arguments: map[string]interface{}{"url": "https://evil.ngrok.io/exfil"},
	}

	_, err := interceptor.Intercept(context.Background(), a)
	if err == nil {
		t.Fatal("expected error")
	}

	if !errors.Is(err, ErrOutboundBlocked) {
		t.Errorf("expected error to unwrap to ErrOutboundBlocked, got: %v", err)
	}
}

func TestOutboundIPBlockedByPrivateNetworkRule(t *testing.T) {
	// Raw IP URL - no DNS resolution needed.
	resolver := newTestResolver(nil)
	next := &outboundMockNext{}

	rules := DefaultBlocklistRules()
	for i := range rules {
		rules[i].Enabled = true
	}
	interceptor := NewOutboundInterceptor(rules, resolver, next, slog.Default())

	a := &CanonicalAction{
		RequestID: "req-14",
		Arguments: map[string]interface{}{"url": "http://192.168.1.100:8080/api"},
	}

	_, err := interceptor.Intercept(context.Background(), a)
	if err == nil {
		t.Fatal("expected error for private network IP")
	}

	var denyErr *OutboundDenyError
	if !errors.As(err, &denyErr) {
		t.Fatalf("expected OutboundDenyError, got %T: %v", err, err)
	}
	if denyErr.RuleName != "Private Network Access" {
		t.Errorf("expected 'Private Network Access' rule, got %q", denyErr.RuleName)
	}
}

func TestOutboundPinsReleasedOnBlock(t *testing.T) {
	resolver := newTestResolver(map[string][]string{
		"evil.ngrok.io": {"1.2.3.4"},
	})
	next := &outboundMockNext{}

	rules := DefaultBlocklistRules()
	for i := range rules {
		rules[i].Enabled = true
	}
	interceptor := NewOutboundInterceptor(rules, resolver, next, slog.Default())

	reqID := "req-15-block-release"
	a := &CanonicalAction{
		RequestID: reqID,
		Arguments: map[string]interface{}{"url": "https://evil.ngrok.io/exfil"},
	}

	_, err := interceptor.Intercept(context.Background(), a)
	if err == nil {
		t.Fatal("expected error")
	}

	// Verify pins were released even on block.
	resolver.mu.RLock()
	_, hasPins := resolver.requestPins[reqID]
	resolver.mu.RUnlock()

	if hasPins {
		t.Error("expected request pins to be released after block")
	}
}

func TestOutboundInterceptor_SetRules(t *testing.T) {
	resolver := newTestResolver(map[string][]string{
		"evil.ngrok.io":    {"1.2.3.4"},
		"good.example.com": {"5.6.7.8"},
	})
	next := &outboundMockNext{}

	// Create interceptor with empty rules (passthrough).
	interceptor := NewOutboundInterceptor(nil, resolver, next, slog.Default())

	// Verify passthrough with no rules.
	a := &CanonicalAction{
		RequestID: "setrules-1",
		Arguments: map[string]interface{}{"url": "https://evil.ngrok.io/exfil"},
	}
	_, err := interceptor.Intercept(context.Background(), a)
	if err != nil {
		t.Fatalf("expected passthrough with empty rules, got error: %v", err)
	}

	// Set blocklist rules that block ngrok.
	interceptor.SetRules([]OutboundRule{
		{
			ID:       "block-ngrok",
			Name:     "Block ngrok",
			Mode:     RuleModeBlocklist,
			Enabled:  true,
			Priority: 100,
			Targets: []OutboundTarget{
				{Type: TargetDomainGlob, Value: "*.ngrok.io"},
			},
		},
	})

	// Verify it now blocks ngrok.
	next2 := &outboundMockNext{}
	interceptor2 := NewOutboundInterceptor(nil, resolver, next2, slog.Default())
	interceptor2.SetRules([]OutboundRule{
		{
			ID:       "block-ngrok",
			Name:     "Block ngrok",
			Mode:     RuleModeBlocklist,
			Enabled:  true,
			Priority: 100,
			Targets: []OutboundTarget{
				{Type: TargetDomainGlob, Value: "*.ngrok.io"},
			},
		},
	})

	a2 := &CanonicalAction{
		RequestID: "setrules-2",
		Arguments: map[string]interface{}{"url": "https://evil.ngrok.io/exfil"},
	}
	_, err = interceptor2.Intercept(context.Background(), a2)
	if err == nil {
		t.Fatal("expected block after SetRules, got passthrough")
	}
	var denyErr *OutboundDenyError
	if !errors.As(err, &denyErr) {
		t.Fatalf("expected OutboundDenyError, got %T: %v", err, err)
	}

	// Set empty rules again -- passthrough restored.
	interceptor2.SetRules(nil)

	a3 := &CanonicalAction{
		RequestID: "setrules-3",
		Arguments: map[string]interface{}{"url": "https://evil.ngrok.io/exfil"},
	}
	_, err = interceptor2.Intercept(context.Background(), a3)
	if err != nil {
		t.Fatalf("expected passthrough after clearing rules, got error: %v", err)
	}
}

func TestOutboundInterceptor_SetRulesConcurrent(t *testing.T) {
	resolver := newTestResolver(map[string][]string{
		"example.com": {"1.2.3.4"},
	})
	next := &outboundMockNext{}
	interceptor := NewOutboundInterceptor(nil, resolver, next, slog.Default())

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// Half goroutines calling SetRules
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			interceptor.SetRules([]OutboundRule{
				{
					ID:       "rule-" + string(rune('A'+idx)),
					Name:     "Concurrent Rule",
					Mode:     RuleModeBlocklist,
					Enabled:  true,
					Priority: idx,
					Targets: []OutboundTarget{
						{Type: TargetDomain, Value: "evil.com"},
					},
				},
			})
		}(i)
	}

	// Half goroutines calling Intercept
	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			a := &CanonicalAction{
				RequestID: "concurrent-" + string(rune('A'+idx)),
				Arguments: map[string]interface{}{"url": "https://example.com/test"},
			}
			// We don't care about the result, just that there's no race.
			_, _ = interceptor.Intercept(context.Background(), a)
		}(i)
	}

	wg.Wait()
}

func TestOutboundBlocklistAlertActionAllowsThrough(t *testing.T) {
	resolver := newTestResolver(map[string][]string{
		"suspicious.example.com": {"1.2.3.4"},
	})
	next := &outboundMockNext{}

	rules := []OutboundRule{
		{
			ID:       "alert-rule",
			Name:     "Alert on suspicious",
			Mode:     RuleModeBlocklist,
			Action:   RuleActionAlert,
			Enabled:  true,
			Priority: 100,
			Targets: []OutboundTarget{
				{Type: TargetDomain, Value: "suspicious.example.com"},
			},
		},
	}

	interceptor := NewOutboundInterceptor(rules, resolver, next, slog.Default())

	a := &CanonicalAction{
		RequestID: "req-alert-1",
		Arguments: map[string]interface{}{"url": "https://suspicious.example.com/data"},
	}

	result, err := interceptor.Intercept(context.Background(), a)
	if err != nil {
		t.Fatalf("alert rule should NOT block, got error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !next.called.Load() {
		t.Fatal("expected next interceptor to be called (alert allows through)")
	}
}

func TestOutboundBlocklistLogActionAllowsThrough(t *testing.T) {
	resolver := newTestResolver(map[string][]string{
		"tracked.example.com": {"5.6.7.8"},
	})
	next := &outboundMockNext{}

	rules := []OutboundRule{
		{
			ID:       "log-rule",
			Name:     "Log tracked domain",
			Mode:     RuleModeBlocklist,
			Action:   RuleActionLog,
			Enabled:  true,
			Priority: 100,
			Targets: []OutboundTarget{
				{Type: TargetDomain, Value: "tracked.example.com"},
			},
		},
	}

	interceptor := NewOutboundInterceptor(rules, resolver, next, slog.Default())

	a := &CanonicalAction{
		RequestID: "req-log-1",
		Arguments: map[string]interface{}{"url": "https://tracked.example.com/api"},
	}

	result, err := interceptor.Intercept(context.Background(), a)
	if err != nil {
		t.Fatalf("log rule should NOT block, got error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if !next.called.Load() {
		t.Fatal("expected next interceptor to be called (log allows through)")
	}
}

func TestOutboundBlocklistBlockActionStillBlocks(t *testing.T) {
	resolver := newTestResolver(map[string][]string{
		"evil.example.com": {"6.6.6.6"},
	})
	next := &outboundMockNext{}

	rules := []OutboundRule{
		{
			ID:       "block-rule",
			Name:     "Block evil",
			Mode:     RuleModeBlocklist,
			Action:   RuleActionBlock,
			Enabled:  true,
			Priority: 100,
			Targets: []OutboundTarget{
				{Type: TargetDomain, Value: "evil.example.com"},
			},
		},
	}

	interceptor := NewOutboundInterceptor(rules, resolver, next, slog.Default())

	a := &CanonicalAction{
		RequestID: "req-block-explicit",
		Arguments: map[string]interface{}{"url": "https://evil.example.com/steal"},
	}

	_, err := interceptor.Intercept(context.Background(), a)
	if err == nil {
		t.Fatal("expected error for explicitly blocked destination")
	}

	var denyErr *OutboundDenyError
	if !errors.As(err, &denyErr) {
		t.Fatalf("expected OutboundDenyError, got %T: %v", err, err)
	}
	if denyErr.RuleName != "Block evil" {
		t.Errorf("expected rule name 'Block evil', got %q", denyErr.RuleName)
	}
}

func TestOutboundBlocklistMixedActions(t *testing.T) {
	resolver := newTestResolver(map[string][]string{
		"evil.example.com": {"6.6.6.6"},
	})
	next := &outboundMockNext{}

	// Alert rule matches but allows through; block rule also matches and blocks.
	rules := []OutboundRule{
		{
			ID:       "alert-first",
			Name:     "Alert wildcard",
			Mode:     RuleModeBlocklist,
			Action:   RuleActionAlert,
			Enabled:  true,
			Priority: 50,
			Targets: []OutboundTarget{
				{Type: TargetDomainGlob, Value: "*.example.com"},
			},
		},
		{
			ID:       "block-evil",
			Name:     "Block evil",
			Mode:     RuleModeBlocklist,
			Action:   RuleActionBlock,
			Enabled:  true,
			Priority: 100,
			Targets: []OutboundTarget{
				{Type: TargetDomain, Value: "evil.example.com"},
			},
		},
	}

	interceptor := NewOutboundInterceptor(rules, resolver, next, slog.Default())

	a := &CanonicalAction{
		RequestID: "req-mixed",
		Arguments: map[string]interface{}{"url": "https://evil.example.com/steal"},
	}

	_, err := interceptor.Intercept(context.Background(), a)
	if err == nil {
		t.Fatal("expected error: alert rule should not prevent subsequent block rule")
	}

	var denyErr *OutboundDenyError
	if !errors.As(err, &denyErr) {
		t.Fatalf("expected OutboundDenyError, got %T: %v", err, err)
	}
	if denyErr.RuleName != "Block evil" {
		t.Errorf("expected 'Block evil' to trigger, got %q", denyErr.RuleName)
	}
}
