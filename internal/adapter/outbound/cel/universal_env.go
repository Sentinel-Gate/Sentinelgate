package cel

import (
	"net"
	"path/filepath"
	"strings"

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

		// dest_domain_matches: glob match against a domain.
		// Usage: dest_domain_matches(dest_domain, "*.evil.com")
		cel.Function("dest_domain_matches",
			cel.Overload("dest_domain_matches_string_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(func(domainVal, patternVal ref.Val) ref.Val {
					domain := domainVal.Value().(string)
					pattern := patternVal.Value().(string)
					matched, _ := filepath.Match(pattern, domain)
					return types.Bool(matched)
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
	)
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
	}
}
