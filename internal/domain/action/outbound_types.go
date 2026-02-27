package action

import (
	"net"
	"strconv"
	"strings"
	"time"
)

// RuleMode determines whether a rule operates as a blocklist or allowlist.
type RuleMode string

const (
	// RuleModeBlocklist blocks matching targets.
	RuleModeBlocklist RuleMode = "blocklist"
	// RuleModeAllowlist allows only matching targets.
	RuleModeAllowlist RuleMode = "allowlist"
)

// RuleAction determines the action to take when a rule matches.
type RuleAction string

const (
	// RuleActionBlock blocks the action entirely.
	RuleActionBlock RuleAction = "block"
	// RuleActionAlert allows the action but raises an alert.
	RuleActionAlert RuleAction = "alert"
	// RuleActionLog allows the action but logs it.
	RuleActionLog RuleAction = "log"
)

// TargetType categorizes the kind of target in an outbound rule.
type TargetType string

const (
	// TargetDomain matches an exact domain name.
	TargetDomain TargetType = "domain"
	// TargetIP matches an exact IP address.
	TargetIP TargetType = "ip"
	// TargetCIDR matches an IP within a CIDR range.
	TargetCIDR TargetType = "cidr"
	// TargetDomainGlob matches a domain against a glob pattern, including subdomains.
	TargetDomainGlob TargetType = "domain_glob"
	// TargetPortRange matches a port within a numeric range.
	TargetPortRange TargetType = "port_range"
)

// OutboundTarget represents a single target specification in an outbound rule.
type OutboundTarget struct {
	// Type is the kind of target (domain, ip, cidr, domain_glob, port_range).
	Type TargetType
	// Value is the target value (e.g., "evil.com", "10.0.0.0/8", "*.ngrok.io", "1-1024").
	Value string
}

// OutboundRule defines a rule for controlling outbound network access.
type OutboundRule struct {
	// ID uniquely identifies this rule.
	ID string
	// Name is the human-readable rule name.
	Name string
	// Mode is blocklist or allowlist.
	Mode RuleMode
	// Targets are the target specifications for this rule.
	Targets []OutboundTarget
	// Action is what happens when the rule matches (block, alert, log).
	Action RuleAction
	// Scope is empty for global rules, otherwise a scope identifier (Phase 4).
	Scope string
	// Priority determines evaluation order (lower = higher priority).
	Priority int
	// Enabled controls whether this rule is active.
	Enabled bool
	// Base64Scan enables base64 URL decoding in URL extraction (OUT-04).
	Base64Scan bool
	// HelpText is shown in deny messages (OUT-10).
	HelpText string
	// HelpURL is a link shown in deny messages (OUT-10).
	HelpURL string
	// ReadOnly is true for default blocklist rules that cannot be modified or deleted.
	ReadOnly bool
	// CreatedAt is when this rule was created.
	CreatedAt time.Time
	// UpdatedAt is when this rule was last modified.
	UpdatedAt time.Time
}

// MatchTarget evaluates whether a single target matches the given destination
// properties (domain, ip, port).
func MatchTarget(target OutboundTarget, domain string, ip string, port int) bool {
	switch target.Type {
	case TargetDomain:
		return strings.EqualFold(target.Value, domain)

	case TargetIP:
		return target.Value == ip

	case TargetCIDR:
		parsedIP := net.ParseIP(ip)
		if parsedIP == nil {
			return false
		}
		_, network, err := net.ParseCIDR(target.Value)
		if err != nil {
			return false
		}
		return network.Contains(parsedIP)

	case TargetDomainGlob:
		return matchDomainGlob(target.Value, domain)

	case TargetPortRange:
		return matchPortRange(target.Value, port)

	default:
		return false
	}
}

// MatchRule returns true if ANY target in the rule matches the given destination.
func MatchRule(rule OutboundRule, domain string, ip string, port int) bool {
	for _, target := range rule.Targets {
		if MatchTarget(target, domain, ip, port) {
			return true
		}
	}
	return false
}

// matchDomainGlob matches a domain against a glob pattern, with subdomain support.
// For pattern "*.ngrok.io", it matches "foo.ngrok.io" and also "bar.foo.ngrok.io".
func matchDomainGlob(pattern, domain string) bool {
	lowerPattern := strings.ToLower(pattern)
	lowerDomain := strings.ToLower(domain)

	// Wildcard pattern: "*.suffix" matches any subdomain of suffix.
	// Uses string suffix matching instead of filepath.Match to correctly
	// handle hyphens and other characters in domain names.
	if strings.HasPrefix(lowerPattern, "*.") {
		suffix := lowerPattern[1:] // ".suffix" (keep the leading dot)
		// Domain must end with the suffix AND have at least one character before it.
		// e.g., "evil.test-domain.invalid" ends with ".test-domain.invalid"
		return len(lowerDomain) > len(suffix) && strings.HasSuffix(lowerDomain, suffix)
	}

	// No wildcard: exact match.
	return lowerPattern == lowerDomain
}

// matchPortRange checks if a port falls within a range specified as "min-max"
// or a single port as "port" or "port-port".
func matchPortRange(value string, port int) bool {
	parts := strings.SplitN(value, "-", 2)
	if len(parts) == 1 {
		// Single port: "8080"
		p, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return false
		}
		return port == p
	}

	minStr := strings.TrimSpace(parts[0])
	maxStr := strings.TrimSpace(parts[1])

	minPort, err := strconv.Atoi(minStr)
	if err != nil {
		return false
	}
	maxPort, err := strconv.Atoi(maxStr)
	if err != nil {
		return false
	}

	return port >= minPort && port <= maxPort
}
