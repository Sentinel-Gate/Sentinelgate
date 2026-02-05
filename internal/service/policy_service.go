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

	"github.com/cespare/xxhash/v2"
	"github.com/google/cel-go/cel"

	celeval "github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/cel"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
)

// CompiledRule represents a pre-compiled policy rule ready for evaluation.
type CompiledRule struct {
	ID        string
	Priority  int
	ToolMatch string      // Glob pattern for tool name matching
	Program   cel.Program // Pre-compiled CEL program
	Action    policy.Action
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

// ResultCache provides bounded caching for CEL evaluation results.
// Thread-safe with RWMutex (reads are frequent, writes are rare).
type ResultCache struct {
	mu      sync.RWMutex
	cache   map[uint64]cachedDecision
	maxSize int
}

type cachedDecision struct {
	decision policy.Decision
	hits     int64 // For LRU-like eviction hint
}

// NewResultCache creates a new cache with the given max size.
func NewResultCache(maxSize int) *ResultCache {
	return &ResultCache{
		cache:   make(map[uint64]cachedDecision),
		maxSize: maxSize,
	}
}

// Get retrieves a cached decision. Returns (decision, true) on hit, (zero, false) on miss.
func (c *ResultCache) Get(key uint64) (policy.Decision, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if entry, ok := c.cache[key]; ok {
		// Note: hits increment is a benign race (LRU hint only)
		return entry.decision, true
	}
	return policy.Decision{}, false
}

// Put stores a decision in the cache. Evicts oldest entries if over capacity.
func (c *ResultCache) Put(key uint64, decision policy.Decision) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Simple eviction: if at capacity, remove ~10% of entries
	if len(c.cache) >= c.maxSize {
		c.evictLocked()
	}

	c.cache[key] = cachedDecision{
		decision: decision,
		hits:     1,
	}
}

// evictLocked removes ~10% of entries. Must be called with lock held.
func (c *ResultCache) evictLocked() {
	toRemove := c.maxSize / 10
	if toRemove < 1 {
		toRemove = 1
	}
	removed := 0
	for key := range c.cache {
		delete(c.cache, key)
		removed++
		if removed >= toRemove {
			break
		}
	}
}

// Clear empties the cache. Called on policy reload.
func (c *ResultCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[uint64]cachedDecision)
}

// Size returns current cache size.
func (c *ResultCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache)
}

// computeCacheKey generates a unique hash for the evaluation context.
// Includes tool name, sorted roles, and args hash for collision resistance.
func computeCacheKey(toolName string, roles []string, args map[string]interface{}) uint64 {
	h := xxhash.New()

	// Tool name
	h.WriteString(toolName)
	h.Write([]byte{0}) // separator

	// Sorted roles (deterministic)
	sortedRoles := make([]string, len(roles))
	copy(sortedRoles, roles)
	sort.Strings(sortedRoles)
	h.WriteString(strings.Join(sortedRoles, ","))
	h.Write([]byte{0})

	// Args hash (JSON for determinism)
	if args != nil && len(args) > 0 {
		argsJSON, _ := json.Marshal(args)
		h.Write(argsJSON)
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
func NewPolicyService(store policy.PolicyStore, logger *slog.Logger, opts ...PolicyServiceOption) (*PolicyService, error) {
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
	ctx := context.Background()
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
			ID:        ruleID,
			Priority:  rule.Priority,
			ToolMatch: rule.ToolMatch,
			Program:   prg,
			Action:    rule.Action,
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
// Results are cached by tool name, roles, and arguments.
func (s *PolicyService) Evaluate(ctx context.Context, evalCtx policy.EvaluationContext) (policy.Decision, error) {
	// Compute cache key from evaluation context
	cacheKey := computeCacheKey(evalCtx.ToolName, evalCtx.UserRoles, evalCtx.ToolArguments)

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
			matched, err := filepath.Match(rule.ToolMatch, evalCtx.ToolName)
			if err != nil {
				s.logger.Warn("invalid glob pattern", "rule", rule.ID, "pattern", rule.ToolMatch, "error", err)
				continue
			}
			if !matched {
				continue
			}
		}

		// Evaluate CEL condition
		result, err := s.evaluator.Evaluate(rule.Program, evalCtx)
		if err != nil {
			return policy.Decision{}, fmt.Errorf("rule %s evaluation failed: %w", rule.ID, err)
		}

		if result {
			// Standard allow/deny handling
			allowed := rule.Action == policy.ActionAllow
			decision := policy.Decision{
				Allowed: allowed,
				RuleID:  rule.ID,
				Reason:  fmt.Sprintf("matched rule %s", rule.ID),
			}
			// Cache the result before returning
			s.cache.Put(cacheKey, decision)
			return decision, nil
		}
	}

	// Default deny
	decision := policy.Decision{
		Allowed: false,
		RuleID:  "",
		Reason:  "no matching rule (default deny)",
	}
	// Cache the default deny result
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

// DefaultPolicy returns a policy with the 10 built-in RBAC rules.
// Note: Rule IDs are left empty so they get auto-generated UUIDs on insert.
// The Name field is used to identify rule purpose.
func DefaultPolicy() *policy.Policy {
	return &policy.Policy{
		ID:      "",
		Name:    "Default RBAC Policy",
		Enabled: true,
		Rules: []policy.Rule{
			// 1. Admin bypass - admins can do anything (highest priority)
			{
				Name:      "admin-bypass",
				Priority:  1000,
				ToolMatch: "*",
				Condition: `"admin" in user_roles`,
				Action:    policy.ActionAllow,
			},
			// 2. Block dangerous tools for non-admins (high priority)
			{
				Name:      "block-delete",
				Priority:  200,
				ToolMatch: "delete_*",
				Condition: `!("admin" in user_roles)`,
				Action:    policy.ActionDeny,
			},
			// 3. Block exec for non-admins
			{
				Name:      "block-exec",
				Priority:  200,
				ToolMatch: "exec_*",
				Condition: `!("admin" in user_roles)`,
				Action:    policy.ActionDeny,
			},
			// 4. Read-only role - read operations
			{
				Name:      "readonly-read",
				Priority:  100,
				ToolMatch: "read_*",
				Condition: `"read-only" in user_roles`,
				Action:    policy.ActionAllow,
			},
			// 5. Read-only role - list operations
			{
				Name:      "readonly-list",
				Priority:  100,
				ToolMatch: "list_*",
				Condition: `"read-only" in user_roles`,
				Action:    policy.ActionAllow,
			},
			// 6. Read-only role - get operations
			{
				Name:      "readonly-get",
				Priority:  100,
				ToolMatch: "get_*",
				Condition: `"read-only" in user_roles`,
				Action:    policy.ActionAllow,
			},
			// 7. User role - read operations
			{
				Name:      "user-read",
				Priority:  50,
				ToolMatch: "read_*",
				Condition: `"user" in user_roles`,
				Action:    policy.ActionAllow,
			},
			// 8. User role - write operations
			{
				Name:      "user-write",
				Priority:  50,
				ToolMatch: "write_*",
				Condition: `"user" in user_roles`,
				Action:    policy.ActionAllow,
			},
			// 9. User role - create operations
			{
				Name:      "user-create",
				Priority:  50,
				ToolMatch: "create_*",
				Condition: `"user" in user_roles`,
				Action:    policy.ActionAllow,
			},
			// 10. Default deny - catch-all (lowest priority)
			{
				Name:      "default-deny",
				Priority:  0,
				ToolMatch: "*",
				Condition: "true",
				Action:    policy.ActionDeny,
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
