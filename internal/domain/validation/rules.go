package validation

// ValidMCPMethods contains all valid MCP 2025-11-25 method names.
// This is a whitelist of methods that are allowed through the proxy.
// Unknown methods are rejected with ErrCodeMethodNotFound.
//
// Reference: https://modelcontextprotocol.io/specification/2025-11-25
var ValidMCPMethods = map[string]bool{
	// Lifecycle
	"initialize":                true,
	"initialized":               true,
	"notifications/initialized": true,
	"ping":                      true,

	// Tools
	"tools/list": true,
	"tools/call": true,

	// Resources
	"resources/list": true,
	"resources/read": true,

	// Prompts
	"prompts/list": true,
	"prompts/get":  true,

	// Completion
	"completion/complete": true,

	// Logging
	"logging/setLevel": true,

	// Notifications
	"notifications/cancelled":              true,
	"notifications/progress":               true,
	"notifications/message":                true,
	"notifications/resources/updated":      true,
	"notifications/resources/list_changed": true,
	"notifications/tools/list_changed":     true,
	"notifications/prompts/list_changed":   true,

	// Sampling (client feature)
	"sampling/createMessage": true,

	// Roots (client feature)
	"roots/list":                       true,
	"notifications/roots/list_changed": true,
}

// IsValidMCPMethod returns true if the method is a valid MCP method.
// MCP method names are case-sensitive.
func IsValidMCPMethod(method string) bool {
	return ValidMCPMethods[method]
}
