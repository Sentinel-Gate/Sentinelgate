package action

import "testing"

func TestDefaultBlocklistRules_NonEmpty(t *testing.T) {
	rules := DefaultBlocklistRules()
	if len(rules) == 0 {
		t.Fatal("expected non-empty default blocklist rules")
	}
}

func TestDefaultBlocklistRules_RuleProperties(t *testing.T) {
	rules := DefaultBlocklistRules()
	seen := make(map[string]bool)

	for _, rule := range rules {
		// Each rule has unique ID
		if seen[rule.ID] {
			t.Errorf("duplicate rule ID: %s", rule.ID)
		}
		seen[rule.ID] = true

		// Non-empty name
		if rule.Name == "" {
			t.Errorf("rule %s has empty name", rule.ID)
		}

		// Blocklist mode
		if rule.Mode != RuleModeBlocklist {
			t.Errorf("rule %s mode = %q, want blocklist", rule.ID, rule.Mode)
		}

		// Block action
		if rule.Action != RuleActionBlock {
			t.Errorf("rule %s action = %q, want block", rule.ID, rule.Action)
		}

		// Disabled by default (user opts in)
		if rule.Enabled {
			t.Errorf("rule %s should be disabled by default", rule.ID)
		}

		// Non-empty HelpText
		if rule.HelpText == "" {
			t.Errorf("rule %s has empty HelpText", rule.ID)
		}

		// Non-empty HelpURL
		if rule.HelpURL == "" {
			t.Errorf("rule %s has empty HelpURL", rule.ID)
		}
	}
}

func TestDefaultBlocklistRules_DataExfiltration(t *testing.T) {
	rules := DefaultBlocklistRules()
	var exfilRule *OutboundRule
	for i := range rules {
		if rules[i].ID == "default-blocklist-1" {
			exfilRule = &rules[i]
			break
		}
	}
	if exfilRule == nil {
		t.Fatal("data exfiltration rule not found")
	}

	// Should match known exfiltration domains
	matches := []struct {
		domain string
		ip     string
	}{
		{"foo.ngrok.io", ""},
		{"t.me", ""},
		{"pastebin.com", ""},
		{"abc.telegram.org", ""},
		{"test.trycloudflare.com", ""},
		{"serveo.net", ""},
		{"hastebin.com", ""},
		{"x.requestbin.com", ""},
		{"x.pipedream.com", ""},
		{"x.ngrok-free.app", ""},
	}
	for _, m := range matches {
		if !MatchRule(*exfilRule, m.domain, m.ip, 0) {
			t.Errorf("expected data exfiltration rule to match domain %q", m.domain)
		}
	}

	// Should NOT match legitimate domains
	nonMatches := []string{"google.com", "github.com", "example.com"}
	for _, domain := range nonMatches {
		if MatchRule(*exfilRule, domain, "", 0) {
			t.Errorf("data exfiltration rule should not match %q", domain)
		}
	}
}

func TestDefaultBlocklistRules_PrivateNetwork(t *testing.T) {
	rules := DefaultBlocklistRules()
	var pvtRule *OutboundRule
	for i := range rules {
		if rules[i].ID == "default-blocklist-2" {
			pvtRule = &rules[i]
			break
		}
	}
	if pvtRule == nil {
		t.Fatal("private network rule not found")
	}

	// Should match private/reserved IPs
	privateIPs := []string{"10.0.0.1", "192.168.1.1", "127.0.0.1", "172.16.5.10", "169.254.1.1"}
	for _, ip := range privateIPs {
		if !MatchRule(*pvtRule, "", ip, 0) {
			t.Errorf("expected private network rule to match IP %q", ip)
		}
	}

	// Should NOT match public IPs
	publicIPs := []string{"8.8.8.8", "1.1.1.1", "203.0.113.1"}
	for _, ip := range publicIPs {
		if MatchRule(*pvtRule, "", ip, 0) {
			t.Errorf("private network rule should not match public IP %q", ip)
		}
	}
}
