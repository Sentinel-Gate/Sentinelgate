package action

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync/atomic"
)

// ErrOutboundBlocked is the sentinel error for outbound-blocked actions.
var ErrOutboundBlocked = fmt.Errorf("outbound blocked")

// OutboundDenyError provides structured deny information for outbound blocks.
type OutboundDenyError struct {
	Domain   string
	IP       string
	Port     int
	RuleName string
	HelpText string
	HelpURL  string
	Reason   string
}

// Error implements the error interface.
func (e *OutboundDenyError) Error() string {
	msg := fmt.Sprintf("outbound blocked: %s (rule: %s)", e.Reason, e.RuleName)
	if e.HelpText != "" {
		msg += " - " + e.HelpText
	}
	if e.HelpURL != "" {
		msg += " [" + e.HelpURL + "]"
	}
	return msg
}

// Unwrap returns the sentinel error for errors.Is() support.
func (e *OutboundDenyError) Unwrap() error {
	return ErrOutboundBlocked
}

// OutboundInterceptor extracts URLs from action arguments, resolves DNS,
// evaluates against outbound rules, and blocks denied destinations.
// It populates action.Destination fields so that downstream CEL policy
// evaluation can use dest_* variables.
//
// Rules are stored via an atomic pointer for lock-free reads during the
// hot path. The SetRules method enables dynamic rule replacement without
// locking the interceptor.
type OutboundInterceptor struct {
	rules    atomic.Pointer[[]OutboundRule]
	resolver *DNSResolver
	next     ActionInterceptor
	logger   *slog.Logger
}

// Compile-time check that OutboundInterceptor implements ActionInterceptor.
var _ ActionInterceptor = (*OutboundInterceptor)(nil)

// NewOutboundInterceptor creates a new OutboundInterceptor.
// The initial rules are stored via atomic pointer. nil is treated as empty.
func NewOutboundInterceptor(rules []OutboundRule, resolver *DNSResolver, next ActionInterceptor, logger *slog.Logger) *OutboundInterceptor {
	if logger == nil {
		logger = slog.Default()
	}
	if rules == nil {
		rules = []OutboundRule{}
	}
	// Sort initial rules by priority ascending for consistent evaluation.
	sorted := make([]OutboundRule, len(rules))
	copy(sorted, rules)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Priority < sorted[j].Priority
	})
	o := &OutboundInterceptor{
		resolver: resolver,
		next:     next,
		logger:   logger,
	}
	o.rules.Store(&sorted)
	return o
}

// SetRules atomically replaces the interceptor's rules with the provided set.
// Rules are sorted by Priority ascending before storage. This enables the admin
// service to reload rules without locking the interceptor's hot path.
func (o *OutboundInterceptor) SetRules(rules []OutboundRule) {
	sorted := make([]OutboundRule, len(rules))
	copy(sorted, rules)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Priority < sorted[j].Priority
	})
	o.rules.Store(&sorted)
}

// Intercept processes a CanonicalAction by extracting URLs, resolving DNS,
// evaluating outbound rules, and populating Destination fields.
func (o *OutboundInterceptor) Intercept(ctx context.Context, a *CanonicalAction) (*CanonicalAction, error) {
	// Skip outbound checking for reverse proxy targets. The admin explicitly
	// configured the upstream destination, so it should not be subject to
	// outbound rules (which protect against agent-initiated exfiltration).
	if skip, ok := a.Metadata["skip_outbound_check"].(bool); ok && skip {
		return o.next.Intercept(ctx, a)
	}

	// Load rules via atomic pointer (lock-free).
	rules := *o.rules.Load()

	// Derive extract options from rules: enable base64 scanning if any rule requests it.
	opts := ExtractOptions{}
	for _, r := range rules {
		if r.Base64Scan {
			opts.Base64Decode = true
			break
		}
	}

	// Extract URLs from action arguments.
	urls := ExtractURLs(a.Arguments, opts)
	if len(urls) == 0 {
		// No extracted URLs — check if Destination was pre-populated by the
		// normalizer (e.g., HTTP CONNECT requests, reverse proxy targets).
		// This ensures outbound rules also block CONNECT tunnels to denied domains.
		if a.Destination.Domain != "" || a.Destination.IP != "" {
			domain := a.Destination.Domain
			ip := a.Destination.IP
			port := a.Destination.Port

			// Resolve domain to IP if needed.
			if domain != "" && ip == "" {
				resolved, err := o.resolver.Resolve(ctx, domain, a.RequestID)
				if err != nil {
					o.logger.Warn("dns resolution failed for pre-populated destination",
						"domain", domain,
						"error", err,
						"request_id", a.RequestID,
					)
				} else {
					ip = resolved.PinnedIP
				}
			}

			blocked, rule := EvaluateDestination(rules, domain, ip, port, o.logger)
			if blocked && rule != nil {
				reason := fmt.Sprintf("destination %s matches blocked target", formatDest(domain, ip, port))
				o.logger.Warn("outbound action blocked (pre-populated destination)",
					"rule_name", rule.Name,
					"rule_id", rule.ID,
					"domain", domain,
					"ip", ip,
					"port", port,
					"request_id", a.RequestID,
					"action_name", a.Name,
				)
				o.resolver.ReleaseRequest(a.RequestID)
				return nil, &OutboundDenyError{
					Domain:   domain,
					IP:       ip,
					Port:     port,
					RuleName: rule.Name,
					HelpText: rule.HelpText,
					HelpURL:  rule.HelpURL,
					Reason:   reason,
				}
			}
		}

		return o.next.Intercept(ctx, a)
	}

	// Process each extracted URL.
	for i, u := range urls {
		domain := u.Domain
		ip := u.IP
		port := u.Port

		// Resolve domain to IP if we have a domain (not raw IP).
		if domain != "" {
			resolved, err := o.resolver.Resolve(ctx, domain, a.RequestID)
			if err != nil {
				o.logger.Warn("dns resolution failed for outbound check",
					"domain", domain,
					"error", err,
					"request_id", a.RequestID,
				)
				// DNS failure is not a block - allow through with warning.
				// The domain might be internal or unavailable.
			} else {
				ip = resolved.PinnedIP
			}
		}

		// Populate Destination from the first URL (for CEL dest_* variables).
		if i == 0 {
			a.Destination = Destination{
				URL:    u.URL,
				Domain: domain,
				IP:     ip,
				Port:   port,
				Scheme: u.Scheme,
				Path:   u.Path,
			}
		}

		// Evaluate against outbound rules.
		blocked, rule := EvaluateDestination(rules, domain, ip, port, o.logger)
		if blocked && rule != nil {
			reason := fmt.Sprintf("destination %s matches blocked target", formatDest(domain, ip, port))

			o.logger.Warn("outbound action blocked",
				"rule_name", rule.Name,
				"rule_id", rule.ID,
				"domain", domain,
				"ip", ip,
				"port", port,
				"request_id", a.RequestID,
				"action_name", a.Name,
			)

			// Release DNS pins before returning error.
			o.resolver.ReleaseRequest(a.RequestID)

			return nil, &OutboundDenyError{
				Domain:   domain,
				IP:       ip,
				Port:     port,
				RuleName: rule.Name,
				HelpText: rule.HelpText,
				HelpURL:  rule.HelpURL,
				Reason:   reason,
			}
		}
	}

	// Release DNS pins after evaluation is done.
	defer o.resolver.ReleaseRequest(a.RequestID)

	return o.next.Intercept(ctx, a)
}

// evaluateDestination checks a destination against the given outbound rules,
// grouping by scope and evaluating by mode.
// Returns (true, rule) if blocked, (false, nil) if allowed.
// For blocklist rules with action "alert" or "log", the match is logged but
// the destination is not blocked.
func EvaluateDestination(rules []OutboundRule, domain, ip string, port int, logger *slog.Logger) (bool, *OutboundRule) {
	if logger == nil {
		logger = slog.Default()
	}
	if len(rules) == 0 {
		return false, nil
	}

	// Rules are already sorted by priority (SetRules / NewOutboundInterceptor).
	// Group rules by scope.
	scopes := make(map[string][]OutboundRule)
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		scopes[r.Scope] = append(scopes[r.Scope], r)
	}

	// Always evaluate global scope ("").
	// Then evaluate any non-global scopes.
	scopeOrder := []string{""}
	for scope := range scopes {
		if scope != "" {
			scopeOrder = append(scopeOrder, scope)
		}
	}

	for _, scope := range scopeOrder {
		scopeRules, ok := scopes[scope]
		if !ok || len(scopeRules) == 0 {
			continue
		}

		// Determine mode from first rule in scope (all rules in a scope share the same mode).
		mode := scopeRules[0].Mode

		if mode == RuleModeBlocklist {
			// Blocklist: matching rules are evaluated per their Action.
			for i, r := range scopeRules {
				if MatchRule(r, domain, ip, port) {
					switch r.Action {
					case RuleActionAlert:
						logger.Warn("outbound rule matched (alert)",
							"rule_name", r.Name,
							"rule_id", r.ID,
							"domain", domain,
							"ip", ip,
							"port", port,
							"action", "alert",
						)
					case RuleActionLog:
						logger.Info("outbound rule matched (log)",
							"rule_name", r.Name,
							"rule_id", r.ID,
							"domain", domain,
							"ip", ip,
							"port", port,
							"action", "log",
						)
					default: // RuleActionBlock or empty
						return true, &scopeRules[i]
					}
				}
			}
		} else if mode == RuleModeAllowlist {
			// Allowlist: if NO rule matches, destination is blocked.
			// Return the first rule as the "reason" (it's the scope's allowlist).
			matched := false
			for _, r := range scopeRules {
				if MatchRule(r, domain, ip, port) {
					matched = true
					break
				}
			}
			if !matched {
				return true, &scopeRules[0]
			}
		}
	}

	return false, nil
}

// formatDest creates a human-readable destination string.
func formatDest(domain, ip string, port int) string {
	if domain != "" {
		if port > 0 {
			return fmt.Sprintf("%s (%s:%d)", domain, ip, port)
		}
		return fmt.Sprintf("%s (%s)", domain, ip)
	}
	if port > 0 {
		return fmt.Sprintf("%s:%d", ip, port)
	}
	return ip
}
