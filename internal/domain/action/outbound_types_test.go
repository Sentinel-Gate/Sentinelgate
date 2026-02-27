package action

import "testing"

func TestMatchTarget_DomainExact(t *testing.T) {
	target := OutboundTarget{Type: TargetDomain, Value: "evil.com"}
	if !MatchTarget(target, "evil.com", "", 0) {
		t.Error("expected exact domain match")
	}
	if !MatchTarget(target, "Evil.COM", "", 0) {
		t.Error("expected case-insensitive domain match")
	}
	if MatchTarget(target, "notevil.com", "", 0) {
		t.Error("expected no match for different domain")
	}
}

func TestMatchTarget_IPExact(t *testing.T) {
	target := OutboundTarget{Type: TargetIP, Value: "192.168.1.1"}
	if !MatchTarget(target, "", "192.168.1.1", 0) {
		t.Error("expected exact IP match")
	}
	if MatchTarget(target, "", "10.0.0.1", 0) {
		t.Error("expected no match for different IP")
	}
}

func TestMatchTarget_CIDR(t *testing.T) {
	target := OutboundTarget{Type: TargetCIDR, Value: "10.0.0.0/8"}
	if !MatchTarget(target, "", "10.0.0.1", 0) {
		t.Error("expected CIDR match for 10.0.0.1 in 10.0.0.0/8")
	}
	if MatchTarget(target, "", "192.168.1.1", 0) {
		t.Error("expected no CIDR match for 192.168.1.1 in 10.0.0.0/8")
	}
}

func TestMatchTarget_CIDR_Invalid(t *testing.T) {
	// Invalid CIDR should return false, not panic
	target := OutboundTarget{Type: TargetCIDR, Value: "not-a-cidr"}
	if MatchTarget(target, "", "10.0.0.1", 0) {
		t.Error("expected false for invalid CIDR")
	}

	// Invalid IP should return false
	target2 := OutboundTarget{Type: TargetCIDR, Value: "10.0.0.0/8"}
	if MatchTarget(target2, "", "not-an-ip", 0) {
		t.Error("expected false for invalid IP against valid CIDR")
	}
}

func TestMatchTarget_DomainGlob(t *testing.T) {
	target := OutboundTarget{Type: TargetDomainGlob, Value: "*.ngrok.io"}

	if !MatchTarget(target, "foo.ngrok.io", "", 0) {
		t.Error("expected glob match for foo.ngrok.io")
	}
	if !MatchTarget(target, "bar.foo.ngrok.io", "", 0) {
		t.Error("expected glob match for nested subdomain bar.foo.ngrok.io")
	}
	if MatchTarget(target, "ngrok.io", "", 0) {
		t.Error("expected no glob match for bare ngrok.io against *.ngrok.io")
	}
	if MatchTarget(target, "notngrok.io", "", 0) {
		t.Error("expected no match for notngrok.io")
	}
}

func TestMatchTarget_DomainGlob_Hyphenated(t *testing.T) {
	target := OutboundTarget{Type: TargetDomainGlob, Value: "*.test-domain.invalid"}

	if !MatchTarget(target, "evil.test-domain.invalid", "", 0) {
		t.Error("expected glob match for evil.test-domain.invalid")
	}
	if !MatchTarget(target, "sub.evil.test-domain.invalid", "", 0) {
		t.Error("expected glob match for nested sub.evil.test-domain.invalid")
	}
	if MatchTarget(target, "test-domain.invalid", "", 0) {
		t.Error("expected no match for bare test-domain.invalid")
	}
	if MatchTarget(target, "other-domain.invalid", "", 0) {
		t.Error("expected no match for other-domain.invalid")
	}
}

func TestMatchTarget_DomainGlob_CaseInsensitive(t *testing.T) {
	target := OutboundTarget{Type: TargetDomainGlob, Value: "*.Ngrok.IO"}
	if !MatchTarget(target, "FOO.NGROK.IO", "", 0) {
		t.Error("expected case-insensitive glob match")
	}
}

func TestMatchTarget_PortRange(t *testing.T) {
	target := OutboundTarget{Type: TargetPortRange, Value: "8000-9000"}
	if !MatchTarget(target, "", "", 8080) {
		t.Error("expected port range match for 8080 in 8000-9000")
	}
	if !MatchTarget(target, "", "", 8000) {
		t.Error("expected port range match for 8000 (inclusive lower)")
	}
	if !MatchTarget(target, "", "", 9000) {
		t.Error("expected port range match for 9000 (inclusive upper)")
	}
	if MatchTarget(target, "", "", 80) {
		t.Error("expected no port range match for 80 in 8000-9000")
	}
}

func TestMatchTarget_PortRange_Single(t *testing.T) {
	target := OutboundTarget{Type: TargetPortRange, Value: "443"}
	if !MatchTarget(target, "", "", 443) {
		t.Error("expected single port match for 443")
	}
	if MatchTarget(target, "", "", 80) {
		t.Error("expected no match for 80 against single port 443")
	}
}

func TestMatchTarget_PortRange_Invalid(t *testing.T) {
	target := OutboundTarget{Type: TargetPortRange, Value: "abc-xyz"}
	if MatchTarget(target, "", "", 80) {
		t.Error("expected false for invalid port range")
	}
}

func TestMatchRule_MultipleTargets(t *testing.T) {
	rule := OutboundRule{
		Targets: []OutboundTarget{
			{Type: TargetDomain, Value: "evil.com"},
			{Type: TargetIP, Value: "10.0.0.1"},
			{Type: TargetPortRange, Value: "443"},
		},
	}

	// Should match on domain
	if !MatchRule(rule, "evil.com", "", 0) {
		t.Error("expected rule match on domain target")
	}
	// Should match on IP
	if !MatchRule(rule, "", "10.0.0.1", 0) {
		t.Error("expected rule match on IP target")
	}
	// Should match on port
	if !MatchRule(rule, "", "", 443) {
		t.Error("expected rule match on port target")
	}
	// Should not match anything else
	if MatchRule(rule, "google.com", "8.8.8.8", 80) {
		t.Error("expected no rule match for non-matching inputs")
	}
}

func TestMatchRule_NoTargets(t *testing.T) {
	rule := OutboundRule{Targets: nil}
	if MatchRule(rule, "evil.com", "10.0.0.1", 443) {
		t.Error("expected false for rule with no targets")
	}
}
