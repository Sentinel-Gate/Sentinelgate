// Package service contains application services.
package service

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/google/cel-go/cel"

	celeval "github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/cel"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
)

// CompiledRule represents a pre-compiled policy rule ready for evaluation.
type CompiledRule struct {
	ID              string
	Name            string // Human-readable rule name
	Priority        int
	ToolMatch       string      // Glob pattern for tool name matching
	Program         cel.Program // Pre-compiled CEL program
	Action          policy.Action
	ApprovalTimeout time.Duration // How long to wait for approval (0 = default 5m)
	TimeoutAction   policy.Action // What to do when approval times out (deny/allow)
}

// RuleIndex provides O(1) lookup for exact tool matches.
type RuleIndex struct {
	Exact    map[string][]CompiledRule // "read_file" -> rules for exact match
	Wildcard []CompiledRule            // "*" or glob patterns, evaluated in priority order
}

// CompiledRulesSnapshot is the immutable snapshot stored in atomic.Value.
type CompiledRulesSnapshot struct {
	Rules []CompiledRule // All rules sorted by priority (kept for compatibility)
	Index *RuleIndex     // Index for fast lookup
}

// lruEntry is a doubly-linked list node for the LRU cache.
type lruEntry struct {
	key      uint64
	decision policy.Decision
	prev     *lruEntry
	next     *lruEntry
}

// ResultCache provides bounded LRU caching for CEL evaluation results.
// Thread-safe with Mutex (both Get and Put mutate LRU order).
type ResultCache struct {
	mu      sync.Mutex
	entries map[uint64]*lruEntry
	head    *lruEntry // most recently used
	tail    *lruEntry // least recently used
	maxSize int
}

// NewResultCache creates a new LRU cache with the given max size.
func NewResultCache(maxSize int) *ResultCache {
	return &ResultCache{
		entries: make(map[uint64]*lruEntry, maxSize),
		maxSize: maxSize,
	}
}

// Get retrieves a cached decision. Returns (decision, true) on hit, (zero, false) on miss.
// On hit, the entry is promoted to the head (most recently used).
func (c *ResultCache) Get(key uint64) (policy.Decision, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[key]; ok {
		c.moveToHeadLocked(e)
		return e.decision, true
	}
	return policy.Decision{}, false
}

// Put stores a decision in the cache. If at capacity, the least recently used entry is evicted.
func (c *ResultCache) Put(key uint64, decision policy.Decision) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if e, ok := c.entries[key]; ok {
		e.decision = decision
		c.moveToHeadLocked(e)
		return
	}

	// Evict LRU entry if at capacity.
	if len(c.entries) >= c.maxSize {
		c.evictTailLocked()
	}

	e := &lruEntry{key: key, decision: decision}
	c.entries[key] = e
	c.pushHeadLocked(e)
}

// Clear empties the cache. Called on policy reload.
func (c *ResultCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[uint64]*lruEntry, c.maxSize)
	c.head = nil
	c.tail = nil
}

// Size returns current cache size.
func (c *ResultCache) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// moveToHeadLocked moves an existing entry to the head. Must be called with lock held.
func (c *ResultCache) moveToHeadLocked(e *lruEntry) {
	if c.head == e {
		return
	}
	c.unlinkLocked(e)
	c.pushHeadLocked(e)
}

// pushHeadLocked inserts an entry at the head. Must be called with lock held.
func (c *ResultCache) pushHeadLocked(e *lruEntry) {
	e.prev = nil
	e.next = c.head
	if c.head != nil {
		c.head.prev = e
	}
	c.head = e
	if c.tail == nil {
		c.tail = e
	}
}

// unlinkLocked removes an entry from the linked list. Must be called with lock held.
func (c *ResultCache) unlinkLocked(e *lruEntry) {
	if e.prev != nil {
		e.prev.next = e.next
	} else {
		c.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else {
		c.tail = e.prev
	}
	e.prev = nil
	e.next = nil
}

// evictTailLocked removes the least recently used entry. Must be called with lock held.
func (c *ResultCache) evictTailLocked() {
	if c.tail == nil {
		return
	}
	delete(c.entries, c.tail.key)
	c.unlinkLocked(c.tail)
}

// computeCacheKey generates a unique hash for the evaluation context.
// Includes tool name, sorted roles, and args hash for collision resistance.
func computeCacheKey(toolName string, roles []string, args map[string]interface{}, identityName string, actionType string, protocol string, framework string) uint64 {
	h := xxhash.New()

	// Tool name
	_, _ = h.WriteString(toolName)
	_, _ = h.Write([]byte{0}) // separator

	// Sorted roles (deterministic)
	sortedRoles := make([]string, len(roles))
	copy(sortedRoles, roles)
	sort.Strings(sortedRoles)
	_, _ = h.WriteString(strings.Join(sortedRoles, ","))
	_, _ = h.Write([]byte{0})

	// Identity name (policies can condition on identity)
	_, _ = h.WriteString(identityName)
	_, _ = h.Write([]byte{0})

	// Action type, protocol, and framework (policies can condition on these)
	_, _ = h.WriteString(actionType)
	_, _ = h.Write([]byte{0})
	_, _ = h.WriteString(protocol)
	_, _ = h.Write([]byte{0})
	_, _ = h.WriteString(framework)
	_, _ = h.Write([]byte{0})

	// Args hash (JSON for determinism)
	if len(args) > 0 {
		argsJSON, _ := json.Marshal(args)
		_, _ = h.Write(argsJSON)
	}

	return h.Sum64()
}

// PolicyService implements policy.PolicyEngine with CEL-based rule evaluation.
// Rules are compiled at load time and evaluated in priority order (highest first).
// Supports hot-reload via Reload() method for runtime policy updates.
// Uses atomic.Value for lock-free reads on the hot path.
type PolicyService struct {
	store     policy.PolicyStore
	evaluator *celeval.Evaluator
	snapshot  atomic.Value // stores *CompiledRulesSnapshot
	mu        sync.Mutex   // Only for Reload() writes
	cache     *ResultCache // CEL result cache
	logger    *slog.Logger
}

// PolicyServiceOption configures PolicyService.
type PolicyServiceOption func(*PolicyService)

// WithCacheSize sets the maximum number of cached decisions.
func WithCacheSize(size int) PolicyServiceOption {
	return func(s *PolicyService) {
		s.cache = NewResultCache(size)
	}
}

// NewPolicyService creates a new PolicyService that loads and compiles rules from the store.
// The ctx parameter is used for the initial policy loading and can be cancelled to abort startup.
func NewPolicyService(ctx context.Context, store policy.PolicyStore, logger *slog.Logger, opts ...PolicyServiceOption) (*PolicyService, error) {
	evaluator, err := celeval.NewEvaluator()
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL evaluator: %w", err)
	}

	s := &PolicyService{
		store:     store,
		evaluator: evaluator,
		cache:     NewResultCache(1000), // Default 1000 entries
		logger:    logger,
	}

	// Apply options (may override default cache)
	for _, opt := range opts {
		opt(s)
	}

	// Load and compile all policies
	policies, err := store.GetAllPolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to load policies: %w", err)
	}

	var allRules []policy.Rule
	for _, p := range policies {
		allRules = append(allRules, p.Rules...)
	}

	compiled, err := s.compileRules(allRules)
	if err != nil {
		return nil, err
	}

	// Build index and store initial snapshot
	snapshot := &CompiledRulesSnapshot{
		Rules: compiled,
		Index: s.buildIndex(compiled),
	}
	s.snapshot.Store(snapshot)

	logger.Info("policy service initialized",
		"rules_compiled", len(compiled),
		"exact_patterns", len(snapshot.Index.Exact),
		"wildcard_patterns", len(snapshot.Index.Wildcard),
		"cache_max_size", s.cache.maxSize,
	)

	return s, nil
}

// ValidateRules checks that all CEL conditions in the given rules are valid.
// This should be called before persisting policies to prevent invalid CEL from
// poisoning the policy store. Returns an error describing the first invalid rule.
func (s *PolicyService) ValidateRules(rules []policy.Rule) error {
	for _, rule := range rules {
		if rule.Condition == "" {
			continue // empty condition defaults to "true" at compile time
		}
		if err := s.evaluator.ValidateExpression(rule.Condition); err != nil {
			return fmt.Errorf("rule %q: %w", rule.Name, err)
		}
	}
	return nil
}

// compileRules compiles CEL expressions and sorts rules by priority.
func (s *PolicyService) compileRules(rules []policy.Rule) ([]CompiledRule, error) {
	compiled := make([]CompiledRule, 0, len(rules))

	for _, rule := range rules {
		prg, err := s.evaluator.Compile(rule.Condition)
		if err != nil {
			return nil, fmt.Errorf("failed to compile rule %s: %w", rule.ID, err)
		}

		// Use Name as identifier if ID is empty (for default policy rules)
		ruleID := rule.ID
		if ruleID == "" {
			ruleID = rule.Name
		}

		compiled = append(compiled, CompiledRule{
			ID:              ruleID,
			Name:            rule.Name,
			Priority:        rule.Priority,
			ToolMatch:       rule.ToolMatch,
			Program:         prg,
			Action:          rule.Action,
			ApprovalTimeout: rule.ApprovalTimeout,
			TimeoutAction:   rule.TimeoutAction,
		})
	}

	// Sort by priority descending (highest first)
	sort.Slice(compiled, func(i, j int) bool {
		return compiled[i].Priority > compiled[j].Priority
	})

	return compiled, nil
}

// buildIndex creates a RuleIndex from compiled rules for O(1) exact match lookup.
func (s *PolicyService) buildIndex(rules []CompiledRule) *RuleIndex {
	idx := &RuleIndex{
		Exact: make(map[string][]CompiledRule),
	}
	for _, rule := range rules {
		// Check if pattern contains wildcards
		if strings.ContainsAny(rule.ToolMatch, "*?[") {
			idx.Wildcard = append(idx.Wildcard, rule)
		} else {
			// Exact match - index by tool name
			idx.Exact[rule.ToolMatch] = append(idx.Exact[rule.ToolMatch], rule)
		}
	}
	// Sort wildcard rules by priority descending
	sort.Slice(idx.Wildcard, func(i, j int) bool {
		return idx.Wildcard[i].Priority > idx.Wildcard[j].Priority
	})
	// Sort each exact match bucket by priority descending
	for k := range idx.Exact {
		sort.Slice(idx.Exact[k], func(i, j int) bool {
			return idx.Exact[k][i].Priority > idx.Exact[k][j].Priority
		})
	}
	return idx
}

// loadSnapshot returns the current rules snapshot atomically (lock-free).
func (s *PolicyService) loadSnapshot() *CompiledRulesSnapshot {
	return s.snapshot.Load().(*CompiledRulesSnapshot)
}

// getCandidateRules returns rules that might match the given tool name,
// merging exact matches with wildcards in priority order.
func (s *PolicyService) getCandidateRules(idx *RuleIndex, toolName string) []CompiledRule {
	// Get exact matches
	exact := idx.Exact[toolName]

	// Merge with wildcards, maintaining priority order
	if len(exact) == 0 {
		return idx.Wildcard
	}
	if len(idx.Wildcard) == 0 {
		return exact
	}

	// Merge both lists maintaining priority order
	merged := make([]CompiledRule, 0, len(exact)+len(idx.Wildcard))
	i, j := 0, 0
	for i < len(exact) && j < len(idx.Wildcard) {
		if exact[i].Priority >= idx.Wildcard[j].Priority {
			merged = append(merged, exact[i])
			i++
		} else {
			merged = append(merged, idx.Wildcard[j])
			j++
		}
	}
	merged = append(merged, exact[i:]...)
	merged = append(merged, idx.Wildcard[j:]...)
	return merged
}

// Evaluate evaluates a tool call against loaded policies.
// Returns Decision with Allowed=true/false and reason.
// Rules are evaluated in priority order, first matching rule wins.
// Default deny if no rules match.
// Uses lock-free atomic.Value read for high performance on the hot path.
// Results are cached by tool name, roles, arguments, identity, action type, and protocol.
func (s *PolicyService) Evaluate(ctx context.Context, evalCtx policy.EvaluationContext) (policy.Decision, error) {
	// Compute cache key from evaluation context
	cacheKey := computeCacheKey(evalCtx.ToolName, evalCtx.UserRoles, evalCtx.ToolArguments, evalCtx.IdentityName, evalCtx.ActionType, evalCtx.Protocol, evalCtx.Framework)

	// Check cache first (hot path optimization)
	if decision, ok := s.cache.Get(cacheKey); ok {
		return decision, nil
	}

	// Lock-free read - no mutex needed
	snapshot := s.loadSnapshot()

	// Get candidate rules from index
	candidates := s.getCandidateRules(snapshot.Index, evalCtx.ToolName)

	// Evaluate candidates in priority order
	for _, rule := range candidates {
		// Check glob pattern match (exact matches already filtered by index)
		if strings.ContainsAny(rule.ToolMatch, "*?[") {
			// Special case: lone "*" matches everything (including paths with /).
			// filepath.Match("*", ...) does not match "/" separators, but for
			// policy rules "*" means "match any tool/action name".
			if rule.ToolMatch != "*" {
				matched, err := filepath.Match(rule.ToolMatch, evalCtx.ToolName)
				if err != nil {
					s.logger.Warn("invalid glob pattern", "rule", rule.ID, "pattern", rule.ToolMatch, "error", err)
					continue
				}
				if !matched {
					continue
				}
			}
		}

		// Evaluate CEL condition
		result, err := s.evaluator.Evaluate(rule.Program, evalCtx)
		if err != nil {
			return policy.Decision{}, fmt.Errorf("rule %s evaluation failed: %w", rule.ID, err)
		}

		if result {
			decision := policy.Decision{
				RuleID:   rule.ID,
				RuleName: rule.Name,
				Reason:   fmt.Sprintf("matched rule %s", rule.Name),
			}

			switch rule.Action {
			case policy.ActionAllow:
				decision.Allowed = true
			case policy.ActionApprovalRequired:
				decision.Allowed = false
				decision.RequiresApproval = true
				decision.ApprovalTimeout = rule.ApprovalTimeout
				decision.ApprovalTimeoutAction = rule.TimeoutAction
			default:
				// ActionDeny or any unknown action
				decision.Allowed = false
			}

			// Cache the result before returning
			s.cache.Put(cacheKey, decision)
			return decision, nil
		}
	}

	// Default allow — no matching rule means the action is permitted.
	// Users can add deny rules via the admin UI to restrict specific tools.
	decision := policy.Decision{
		Allowed: true,
		RuleID:  "",
		Reason:  "no matching rule (default allow)",
	}
	// Cache the default allow result
	s.cache.Put(cacheKey, decision)
	return decision, nil
}

// Reload reloads and recompiles all policies from the store.
// This method is thread-safe and can be called concurrently with Evaluate.
// Only enabled policies are included in the compiled ruleset.
// Uses atomic.Value.Store for lock-free publish to readers.
func (s *PolicyService) Reload(ctx context.Context) error {
	// Load all policies from store (outside lock)
	policies, err := s.store.GetAllPolicies(ctx)
	if err != nil {
		return fmt.Errorf("failed to load policies: %w", err)
	}

	// Collect rules from enabled policies only
	var allRules []policy.Rule
	for _, p := range policies {
		if p.Enabled {
			allRules = append(allRules, p.Rules...)
		}
	}

	// Compile all rules (outside lock)
	compiled, err := s.compileRules(allRules)
	if err != nil {
		return fmt.Errorf("failed to compile rules: %w", err)
	}

	// Build index (outside lock)
	idx := s.buildIndex(compiled)

	// Atomic swap (very brief mutex for Store)
	s.mu.Lock()
	s.snapshot.Store(&CompiledRulesSnapshot{
		Rules: compiled,
		Index: idx,
	})
	s.mu.Unlock()

	// Clear cache on reload (policies changed, cached decisions may be stale)
	s.cache.Clear()

	s.logger.Info("policy service reloaded",
		"policies", len(policies),
		"enabled_policies", countEnabled(policies),
		"rules_compiled", len(compiled),
		"exact_patterns", len(idx.Exact),
		"wildcard_patterns", len(idx.Wildcard),
		"cache_cleared", true,
	)

	return nil
}

// countEnabled counts the number of enabled policies.
func countEnabled(policies []policy.Policy) int {
	count := 0
	for _, p := range policies {
		if p.Enabled {
			count++
		}
	}
	return count
}

// DefaultPolicy returns a policy with the built-in RBAC rules.
// All roles are plain strings with no implicit privileges.
// Note: Rule IDs are left empty so they get auto-generated UUIDs on insert.
// The Name field is used to identify rule purpose.
func DefaultPolicy() *policy.Policy {
	return &policy.Policy{
		ID:      "",
		Name:    "Default RBAC Policy",
		Enabled: true,
		Rules: []policy.Rule{
			// 1. Block dangerous tools (high priority)
			{
				Name:      "block-delete",
				Priority:  200,
				ToolMatch: "delete_*",
				Condition: "true",
				Action:    policy.ActionDeny,
			},
			// 2. Block exec
			{
				Name:      "block-exec",
				Priority:  200,
				ToolMatch: "exec_*",
				Condition: "true",
				Action:    policy.ActionDeny,
			},
			// 3. Read-only role - read operations
			{
				Name:      "readonly-read",
				Priority:  100,
				ToolMatch: "read_*",
				Condition: `"read-only" in user_roles`,
				Action:    policy.ActionAllow,
			},
			// 4. Read-only role - list operations
			{
				Name:      "readonly-list",
				Priority:  100,
				ToolMatch: "list_*",
				Condition: `"read-only" in user_roles`,
				Action:    policy.ActionAllow,
			},
			// 5. Read-only role - get operations
			{
				Name:      "readonly-get",
				Priority:  100,
				ToolMatch: "get_*",
				Condition: `"read-only" in user_roles`,
				Action:    policy.ActionAllow,
			},
			// 6. User role - read operations
			{
				Name:      "user-read",
				Priority:  50,
				ToolMatch: "read_*",
				Condition: `"user" in user_roles`,
				Action:    policy.ActionAllow,
			},
			// 7. User role - write operations
			{
				Name:      "user-write",
				Priority:  50,
				ToolMatch: "write_*",
				Condition: `"user" in user_roles`,
				Action:    policy.ActionAllow,
			},
			// 8. User role - create operations
			{
				Name:      "user-create",
				Priority:  50,
				ToolMatch: "create_*",
				Condition: `"user" in user_roles`,
				Action:    policy.ActionAllow,
			},
		},
	}
}

// SeedDefaultPolicy seeds the default policy if no policies exist in the store.
// This ensures the proxy has rules to evaluate on first boot.
// Returns nil if policies already exist (idempotent).
func SeedDefaultPolicy(ctx context.Context, store policy.PolicyStore, logger *slog.Logger) error {
	// Check if policies already exist
	policies, err := store.GetAllPolicies(ctx)
	if err != nil {
		return fmt.Errorf("check existing policies: %w", err)
	}

	if len(policies) > 0 {
		logger.Debug("policies exist, skipping seed", "count", len(policies))
		return nil
	}

	// Seed default policy
	defaultPolicy := DefaultPolicy()
	if err := store.SavePolicy(ctx, defaultPolicy); err != nil {
		return fmt.Errorf("save default policy: %w", err)
	}

	// Save rules individually (PostgresPolicyStore stores rules separately)
	for i := range defaultPolicy.Rules {
		rule := &defaultPolicy.Rules[i]
		if err := store.SaveRule(ctx, defaultPolicy.ID, rule); err != nil {
			return fmt.Errorf("save rule %s: %w", rule.ID, err)
		}
	}

	logger.Info("seeded default policy", "rules", len(defaultPolicy.Rules))
	return nil
}

// Compile-time interface verification.
var _ policy.PolicyEngine = (*PolicyService)(nil)
