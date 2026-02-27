package cel

import (
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/policy"
)

// NewUniversalPolicyEnvironment creates a CEL environment with all universal variables
// and custom functions for cross-protocol policy evaluation. It includes:
//   - Backward-compatible variables: tool_name, tool_args, user_roles, session_id, identity_id, identity_name, request_time
//   - Universal variables: action_type, action_name, protocol, framework, gateway, arguments, identity_roles
//   - Destination variables: dest_url, dest_domain, dest_ip, dest_port, dest_scheme, dest_path, dest_command
//   - Custom functions: glob, dest_ip_in_cidr, dest_domain_matches, action_arg, action_arg_contains
func NewUniversalPolicyEnvironment() (*cel.Env, error) {
	return cel.NewEnv(
		// Standard extensions
		ext.Strings(),
		ext.Sets(),

		// === Backward-compatible variables (existing) ===
		cel.Variable("tool_name", cel.StringType),
		cel.Variable("tool_args", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("user_roles", cel.ListType(cel.StringType)),
		cel.Variable("session_id", cel.StringType),
		cel.Variable("identity_id", cel.StringType),
		cel.Variable("identity_name", cel.StringType),
		cel.Variable("request_time", cel.TimestampType),

		// === Universal variables (new) ===
		cel.Variable("action_type", cel.StringType),
		cel.Variable("action_name", cel.StringType),
		cel.Variable("protocol", cel.StringType),
		cel.Variable("framework", cel.StringType),
		cel.Variable("gateway", cel.StringType),
		cel.Variable("arguments", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("identity_roles", cel.ListType(cel.StringType)),

		// === Destination variables (new) ===
		cel.Variable("dest_url", cel.StringType),
		cel.Variable("dest_domain", cel.StringType),
		cel.Variable("dest_ip", cel.StringType),
		cel.Variable("dest_port", cel.IntType),
		cel.Variable("dest_scheme", cel.StringType),
		cel.Variable("dest_path", cel.StringType),
		cel.Variable("dest_command", cel.StringType),

		// === Session usage variables (Phase 15: Budget & Quota) ===
		cel.Variable("session_call_count", cel.IntType),
		cel.Variable("session_write_count", cel.IntType),
		cel.Variable("session_delete_count", cel.IntType),
		cel.Variable("session_duration_seconds", cel.IntType),

		// === Session history variables (Phase 17: Session-Aware Policies) ===
		cel.Variable("session_action_history", cel.ListType(cel.DynType)),
		cel.Variable("session_action_set", cel.MapType(cel.StringType, cel.BoolType)),
		cel.Variable("session_arg_key_set", cel.MapType(cel.StringType, cel.BoolType)),

		// === Custom functions ===

		// glob: existing glob pattern matching for tool names
		cel.Function("glob",
			cel.Overload("glob_string_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(func(pattern, name ref.Val) ref.Val {
					p := pattern.Value().(string)
					n := name.Value().(string)
					matched, _ := filepath.Match(p, n)
					return types.Bool(matched)
				}),
			),
		),

		// dest_ip_in_cidr: checks if an IP is within a CIDR range.
		// Usage: dest_ip_in_cidr(dest_ip, "10.0.0.0/8")
		cel.Function("dest_ip_in_cidr",
			cel.Overload("dest_ip_in_cidr_string_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(func(ipVal, cidrVal ref.Val) ref.Val {
					ipStr := ipVal.Value().(string)
					cidrStr := cidrVal.Value().(string)

					ip := net.ParseIP(ipStr)
					if ip == nil {
						return types.Bool(false)
					}

					_, network, err := net.ParseCIDR(cidrStr)
					if err != nil {
						return types.Bool(false)
					}

					return types.Bool(network.Contains(ip))
				}),
			),
		),

		// dest_domain_matches: domain-aware wildcard match.
		// Usage: dest_domain_matches(dest_domain, "*.evil.com")
		// Supports:
		//   - Exact match: "evil.com" matches "evil.com"
		//   - Single-level wildcard: "*.evil.com" matches "sub.evil.com"
		//   - Multi-level wildcard: "*.evil.com" matches "deep.sub.evil.com"
		//   - Hyphenated segments: "*.test-domain.invalid" matches "evil.test-domain.invalid"
		// This replaces filepath.Match which fails for multi-level wildcard patterns.
		cel.Function("dest_domain_matches",
			cel.Overload("dest_domain_matches_string_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(func(domainVal, patternVal ref.Val) ref.Val {
					domain := domainVal.Value().(string)
					pattern := patternVal.Value().(string)
					return types.Bool(domainMatchesWildcard(domain, pattern))
				}),
			),
		),

		// action_arg: extract a specific argument by key from a map.
		// Usage: action_arg(arguments, "url")
		cel.Function("action_arg",
			cel.Overload("action_arg_map_string",
				[]*cel.Type{cel.MapType(cel.StringType, cel.DynType), cel.StringType},
				cel.DynType,
				cel.BinaryBinding(func(mapVal, keyVal ref.Val) ref.Val {
					key := keyVal.Value().(string)
					m, ok := mapVal.Value().(map[ref.Val]ref.Val)
					if ok {
						k := types.String(key)
						if v, found := m[k]; found {
							return v
						}
						return types.NullValue
					}
					// Try the adapter interface
					adapterResult := mapVal.Value()
					if goMap, ok := adapterResult.(map[string]any); ok {
						if v, found := goMap[key]; found {
							return types.DefaultTypeAdapter.NativeToValue(v)
						}
					}
					return types.NullValue
				}),
			),
		),

		// action_arg_contains: check if any argument value contains a substring.
		// Usage: action_arg_contains(arguments, "password")
		cel.Function("action_arg_contains",
			cel.Overload("action_arg_contains_map_string",
				[]*cel.Type{cel.MapType(cel.StringType, cel.DynType), cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(func(mapVal, substrVal ref.Val) ref.Val {
					substr := substrVal.Value().(string)
					goVal := mapVal.Value()
					if goMap, ok := goVal.(map[string]any); ok {
						for _, v := range goMap {
							if s, ok := v.(string); ok {
								if strings.Contains(s, substr) {
									return types.Bool(true)
								}
							}
						}
					}
					if refMap, ok := goVal.(map[ref.Val]ref.Val); ok {
						for _, v := range refMap {
							if s, ok := v.Value().(string); ok {
								if strings.Contains(s, substr) {
									return types.Bool(true)
								}
							}
						}
					}
					return types.Bool(false)
				}),
			),
		),

		// === Session history functions (Phase 17: Session-Aware Policies) ===

		// session_count: count actions by CallType ("read", "write", "delete", "other") in the full session history.
		// Usage: session_count(session_action_history, "read")
		cel.Function("session_count",
			cel.Overload("session_count_list_string",
				[]*cel.Type{cel.ListType(cel.DynType), cel.StringType},
				cel.IntType,
				cel.BinaryBinding(func(listVal, typeVal ref.Val) ref.Val {
					callType := typeVal.Value().(string)
					records := extractActionRecords(listVal)
					count := int64(0)
					for _, rec := range records {
						if ct, ok := rec["call_type"].(string); ok && ct == callType {
							count++
						}
					}
					return types.Int(count)
				}),
			),
		),

		// session_count_for: count actions by tool name in the full session history.
		// Usage: session_count_for(session_action_history, "read_file")
		cel.Function("session_count_for",
			cel.Overload("session_count_for_list_string",
				[]*cel.Type{cel.ListType(cel.DynType), cel.StringType},
				cel.IntType,
				cel.BinaryBinding(func(listVal, nameVal ref.Val) ref.Val {
					toolName := nameVal.Value().(string)
					records := extractActionRecords(listVal)
					count := int64(0)
					for _, rec := range records {
						if tn, ok := rec["tool_name"].(string); ok && tn == toolName {
							count++
						}
					}
					return types.Int(count)
				}),
			),
		),

		// session_count_window: count actions by tool name within the last N seconds.
		// Usage: session_count_window(session_action_history, "write_file", 60)
		cel.Function("session_count_window",
			cel.Overload("session_count_window_list_string_int",
				[]*cel.Type{cel.ListType(cel.DynType), cel.StringType, cel.IntType},
				cel.IntType,
				cel.FunctionBinding(func(args ...ref.Val) ref.Val {
					toolName := args[1].Value().(string)
					seconds := args[2].Value().(int64)
					records := extractActionRecords(args[0])
					cutoff := time.Now().Add(-time.Duration(seconds) * time.Second)
					count := int64(0)
					for _, rec := range records {
						tn, _ := rec["tool_name"].(string)
						ts, _ := rec["timestamp"].(time.Time)
						if tn == toolName && ts.After(cutoff) {
							count++
						}
					}
					return types.Int(count)
				}),
			),
		),

		// session_has_action: check if a tool name exists in the session action set.
		// Usage: session_has_action(session_action_set, "read_file")
		cel.Function("session_has_action",
			cel.Overload("session_has_action_map_string",
				[]*cel.Type{cel.MapType(cel.StringType, cel.BoolType), cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(func(mapVal, nameVal ref.Val) ref.Val {
					name := nameVal.Value().(string)
					goVal := mapVal.Value()
					if goMap, ok := goVal.(map[string]bool); ok {
						return types.Bool(goMap[name])
					}
					if refMap, ok := goVal.(map[ref.Val]ref.Val); ok {
						k := types.String(name)
						if v, found := refMap[k]; found {
							if b, ok := v.Value().(bool); ok {
								return types.Bool(b)
							}
						}
					}
					return types.Bool(false)
				}),
			),
		),

		// session_has_arg: check if an argument key name exists in the session arg key set.
		// Usage: session_has_arg(session_arg_key_set, "content")
		cel.Function("session_has_arg",
			cel.Overload("session_has_arg_map_string",
				[]*cel.Type{cel.MapType(cel.StringType, cel.BoolType), cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(func(mapVal, keyVal ref.Val) ref.Val {
					key := keyVal.Value().(string)
					goVal := mapVal.Value()
					if goMap, ok := goVal.(map[string]bool); ok {
						return types.Bool(goMap[key])
					}
					if refMap, ok := goVal.(map[ref.Val]ref.Val); ok {
						k := types.String(key)
						if v, found := refMap[k]; found {
							if b, ok := v.Value().(bool); ok {
								return types.Bool(b)
							}
						}
					}
					return types.Bool(false)
				}),
			),
		),

		// session_has_arg_in: check if a specific arg key was used with a specific tool in the session.
		// Usage: session_has_arg_in(session_action_history, "content", "write_file")
		cel.Function("session_has_arg_in",
			cel.Overload("session_has_arg_in_list_string_string",
				[]*cel.Type{cel.ListType(cel.DynType), cel.StringType, cel.StringType},
				cel.BoolType,
				cel.FunctionBinding(func(args ...ref.Val) ref.Val {
					field := args[1].Value().(string)
					toolName := args[2].Value().(string)
					records := extractActionRecords(args[0])
					for _, rec := range records {
						tn, _ := rec["tool_name"].(string)
						if tn != toolName {
							continue
						}
						if argKeys, ok := rec["arg_keys"].([]string); ok {
							for _, k := range argKeys {
								if k == field {
									return types.Bool(true)
								}
							}
						}
					}
					return types.Bool(false)
				}),
			),
		),

		// session_sequence: check if action_a occurred before action_b in the session (ordered occurrence).
		// Usage: session_sequence(session_action_history, "read_file", "send_email")
		cel.Function("session_sequence",
			cel.Overload("session_sequence_list_string_string",
				[]*cel.Type{cel.ListType(cel.DynType), cel.StringType, cel.StringType},
				cel.BoolType,
				cel.FunctionBinding(func(args ...ref.Val) ref.Val {
					actionA := args[1].Value().(string)
					actionB := args[2].Value().(string)
					records := extractActionRecords(args[0])
					foundA := false
					for _, rec := range records {
						tn, _ := rec["tool_name"].(string)
						if tn == actionA {
							foundA = true
						}
						if tn == actionB && foundA {
							return types.Bool(true)
						}
					}
					return types.Bool(false)
				}),
			),
		),

		// session_time_since_action: seconds since the last occurrence of the named tool call.
		// Returns -1 if the tool was never called in the session.
		// Usage: session_time_since_action(session_action_history, "send_email")
		cel.Function("session_time_since_action",
			cel.Overload("session_time_since_action_list_string",
				[]*cel.Type{cel.ListType(cel.DynType), cel.StringType},
				cel.IntType,
				cel.BinaryBinding(func(listVal, nameVal ref.Val) ref.Val {
					toolName := nameVal.Value().(string)
					records := extractActionRecords(listVal)
					// Iterate in reverse to find the last occurrence
					for i := len(records) - 1; i >= 0; i-- {
						tn, _ := records[i]["tool_name"].(string)
						if tn == toolName {
							ts, _ := records[i]["timestamp"].(time.Time)
							return types.Int(int64(time.Since(ts).Seconds()))
						}
					}
					return types.Int(-1)
				}),
			),
		),
	)
}

// extractActionRecords extracts a Go []map[string]any from a CEL list value.
// It handles both native Go slices (passed from BuildUniversalActivation) and
// CEL-wrapped list types.
func extractActionRecords(listVal ref.Val) []map[string]any {
	goVal := listVal.Value()
	switch v := goVal.(type) {
	case []map[string]any:
		return v
	case []any:
		result := make([]map[string]any, 0, len(v))
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				result = append(result, m)
			}
		}
		return result
	}
	return nil
}

// domainMatchesWildcard checks whether domain matches pattern using domain-aware
// wildcard semantics. It correctly handles:
//   - Exact match: domain == pattern
//   - Wildcard prefix "*.": matches any subdomain at any depth
//     e.g. "*.evil.com" matches "sub.evil.com" and "deep.sub.evil.com"
//   - Hyphenated segments: "*.test-domain.invalid" matches "evil.test-domain.invalid"
//   - Bare domain: "*.evil.com" does NOT match "evil.com" (subdomain required)
//
// Falls back to filepath.Match for non-wildcard glob patterns.
func domainMatchesWildcard(domain, pattern string) bool {
	// Exact match.
	if domain == pattern {
		return true
	}

	// Wildcard prefix pattern: *.example.com
	if strings.HasPrefix(pattern, "*.") {
		// suffix is ".example.com" (includes the leading dot)
		suffix := pattern[1:]
		// Match any subdomain at any depth: sub.example.com, deep.sub.example.com, etc.
		// The domain must end with the suffix AND have at least one character before it.
		if strings.HasSuffix(domain, suffix) && len(domain) > len(suffix) {
			return true
		}
		// Do NOT match the bare domain (evil.com should not match *.evil.com).
		return false
	}

	// Fallback to filepath.Match for other glob patterns (e.g. "evil?com").
	matched, _ := filepath.Match(pattern, domain)
	return matched
}

// fillDefaults sets default values for universal fields when they are empty.
// This ensures backward compatibility: legacy code that only populates ToolName,
// ToolArguments, and UserRoles will still work with universal CEL rules.
func fillDefaults(evalCtx *policy.EvaluationContext) {
	if evalCtx.ActionType == "" {
		evalCtx.ActionType = "tool_call"
	}
	if evalCtx.ActionName == "" {
		evalCtx.ActionName = evalCtx.ToolName
	}
	if evalCtx.Protocol == "" {
		evalCtx.Protocol = "mcp"
	}
}

// buildSessionActionHistory converts policy.SessionActionRecord slices to []map[string]any
// for CEL evaluation. Each map has keys: "tool_name", "call_type", "timestamp", "arg_keys".
func buildSessionActionHistory(records []policy.SessionActionRecord) []map[string]any {
	if records == nil {
		return []map[string]any{}
	}
	result := make([]map[string]any, len(records))
	for i, rec := range records {
		result[i] = map[string]any{
			"tool_name": rec.ToolName,
			"call_type": rec.CallType,
			"timestamp": rec.Timestamp,
			"arg_keys":  rec.ArgKeys,
		}
	}
	return result
}

// buildSessionSet returns a non-nil map for CEL evaluation.
func buildSessionSet(m map[string]bool) map[string]bool {
	if m == nil {
		return map[string]bool{}
	}
	return m
}

// BuildUniversalActivation creates a CEL activation map from an EvaluationContext.
// It populates all backward-compatible, universal, and destination variables.
// Default filling is applied for empty universal fields.
func BuildUniversalActivation(evalCtx policy.EvaluationContext) map[string]any {
	fillDefaults(&evalCtx)

	// Ensure non-nil maps and slices for CEL
	toolArgs := evalCtx.ToolArguments
	if toolArgs == nil {
		toolArgs = map[string]interface{}{}
	}
	userRoles := evalCtx.UserRoles
	if userRoles == nil {
		userRoles = []string{}
	}

	return map[string]any{
		// Backward-compatible (existing)
		"tool_name":     evalCtx.ToolName,
		"tool_args":     toolArgs,
		"user_roles":    userRoles,
		"session_id":    evalCtx.SessionID,
		"identity_id":   evalCtx.IdentityID,
		"identity_name": evalCtx.IdentityName,
		"request_time":  evalCtx.RequestTime,

		// Universal (new)
		"action_type":    evalCtx.ActionType,
		"action_name":    evalCtx.ActionName,
		"protocol":       evalCtx.Protocol,
		"framework":      evalCtx.Framework,
		"gateway":        evalCtx.Gateway,
		"arguments":      toolArgs,  // alias for tool_args
		"identity_roles": userRoles, // alias for user_roles

		// Destination (new)
		"dest_url":     evalCtx.DestURL,
		"dest_domain":  evalCtx.DestDomain,
		"dest_ip":      evalCtx.DestIP,
		"dest_port":    int64(evalCtx.DestPort),
		"dest_scheme":  evalCtx.DestScheme,
		"dest_path":    evalCtx.DestPath,
		"dest_command": evalCtx.DestCommand,

		// Session usage (Phase 15)
		"session_call_count":       evalCtx.SessionCallCount,
		"session_write_count":      evalCtx.SessionWriteCount,
		"session_delete_count":     evalCtx.SessionDeleteCount,
		"session_duration_seconds": evalCtx.SessionDurationSeconds,

		// Session history (Phase 17)
		"session_action_history": buildSessionActionHistory(evalCtx.SessionActionHistory),
		"session_action_set":     buildSessionSet(evalCtx.SessionActionSet),
		"session_arg_key_set":    buildSessionSet(evalCtx.SessionArgKeySet),
	}
}
