package policy

// PolicyTemplate defines a reusable policy blueprint that users can
// apply with one click instead of writing CEL rules from scratch.
type PolicyTemplate struct {
	// ID is a slug identifier (e.g., "safe-coding", "read-only").
	ID string
	// Name is a human-readable display name.
	Name string
	// Description is a 1-2 sentence explanation of what the template does.
	Description string
	// Category groups templates (e.g., "development", "security", "compliance").
	Category string
	// Rules are the policy rules this template creates.
	Rules []TemplateRule
	// Icon is the icon name from the SG.icon set.
	Icon string
}

// TemplateRule defines a single rule within a policy template.
type TemplateRule struct {
	// Name is a human-readable name for this rule.
	Name string
	// ToolMatch is a glob pattern to match tool names (e.g., "*", "write_file").
	ToolMatch string
	// Condition is a CEL expression (e.g., "true", "tool_name == 'read_file'").
	Condition string
	// Action is allow or deny.
	Action Action
	// Priority determines evaluation order (higher number = evaluated first).
	Priority int
}

// ToPolicy converts a PolicyTemplate into a Policy struct.
// The returned policy has no ID or timestamps — the caller assigns those.
func (t *PolicyTemplate) ToPolicy() *Policy {
	rules := make([]Rule, len(t.Rules))
	for i, tr := range t.Rules {
		rules[i] = Rule{
			Name:      tr.Name,
			ToolMatch: tr.ToolMatch,
			Condition: tr.Condition,
			Action:    tr.Action,
			Priority:  tr.Priority,
			Source:    "template:" + t.ID,
		}
	}
	return &Policy{
		Name:        t.Name,
		Description: t.Description,
		Enabled:     true,
		Rules:       rules,
	}
}

// AllTemplates returns the 7 built-in policy templates.
func AllTemplates() []PolicyTemplate {
	return []PolicyTemplate{
		safeCoding(),
		readOnly(),
		research(),
		lockdown(),
		auditOnly(),
		dataProtection(),
		antiExfiltration(),
	}
}

// GetTemplate looks up a template by ID. Returns nil, false if not found.
func GetTemplate(id string) (*PolicyTemplate, bool) {
	for _, t := range AllTemplates() {
		if t.ID == id {
			return &t, true
		}
	}
	return nil, false
}

func safeCoding() PolicyTemplate {
	return PolicyTemplate{
		ID:          "safe-coding",
		Name:        "Safe Coding",
		Description: "Allows read operations and writes to non-sensitive paths. Ideal for AI coding assistants.",
		Category:    "development",
		Icon:        "code",
		Rules: []TemplateRule{
			{
				Name:      "Allow read operations",
				ToolMatch: "*",
				Condition: "tool_name in ['read_file','list_directory','search_files','list_files','get_file_info']",
				Action:    ActionAllow,
				Priority:  100,
			},
			{
				Name:      "Allow writes to non-sensitive paths",
				ToolMatch: "write_file",
				Condition: `!("path" in arguments) || (!string(arguments["path"]).startsWith("/etc") && !string(arguments["path"]).startsWith("/sys"))`,
				Action:    ActionAllow,
				Priority:  90,
			},
			{
				Name:      "Default deny",
				ToolMatch: "*",
				Condition: "true",
				Action:    ActionDeny,
				Priority:  1,
			},
		},
	}
}

func readOnly() PolicyTemplate {
	return PolicyTemplate{
		ID:          "read-only",
		Name:        "File Server — Read Only",
		Description: "Permits only file-system read operations (read_file, list_directory, etc.). Blocks all other tools including those from other servers.",
		Category:    "security",
		Icon:        "eye",
		Rules: []TemplateRule{
			{
				Name:      "Allow read operations",
				ToolMatch: "*",
				Condition: "tool_name in ['read_file','read_text_file','read_multiple_files','read_media_file','list_directory','list_directory_with_sizes','list_allowed_directories','search_files','list_files','get_file_info']",
				Action:    ActionAllow,
				Priority:  100,
			},
			{
				Name:      "Deny everything else",
				ToolMatch: "*",
				Condition: "true",
				Action:    ActionDeny,
				Priority:  1,
			},
		},
	}
}

func research() PolicyTemplate {
	return PolicyTemplate{
		ID:          "research",
		Name:        "Research Mode",
		Description: "Allows reading, web searches, and writing to temporary directories. Blocks all other modifications.",
		Category:    "development",
		Icon:        "search",
		Rules: []TemplateRule{
			{
				Name:      "Allow read operations",
				ToolMatch: "*",
				Condition: "tool_name in ['read_file','list_directory','search_files','list_files','get_file_info']",
				Action:    ActionAllow,
				Priority:  100,
			},
			{
				Name:      "Allow web and search tools",
				ToolMatch: "*",
				Condition: "tool_name in ['web_search','fetch_url','http_get']",
				Action:    ActionAllow,
				Priority:  90,
			},
			{
				Name:      "Allow writes to temp directories",
				ToolMatch: "write_file",
				Condition: `"path" in arguments && string(arguments["path"]).startsWith("/tmp")`,
				Action:    ActionAllow,
				Priority:  80,
			},
			{
				Name:      "Deny everything else",
				ToolMatch: "*",
				Condition: "true",
				Action:    ActionDeny,
				Priority:  1,
			},
		},
	}
}

func lockdown() PolicyTemplate {
	return PolicyTemplate{
		ID:          "lockdown",
		Name:        "Full Lockdown",
		Description: "Blocks all tool calls unconditionally. Use when you need to completely disable agent activity.",
		Category:    "security",
		Icon:        "lock",
		Rules: []TemplateRule{
			{
				Name:      "Deny all",
				ToolMatch: "*",
				Condition: "true",
				Action:    ActionDeny,
				Priority:  1,
			},
		},
	}
}

func auditOnly() PolicyTemplate {
	return PolicyTemplate{
		ID:          "audit-only",
		Name:        "Audit Only",
		Description: "Allows all tool calls but logs everything for monitoring. No blocking, full visibility.",
		Category:    "compliance",
		Icon:        "clipboard",
		Rules: []TemplateRule{
			{
				Name:      "Allow all for monitoring",
				ToolMatch: "*",
				Condition: "true",
				Action:    ActionAllow,
				Priority:  1,
			},
		},
	}
}

func dataProtection() PolicyTemplate {
	return PolicyTemplate{
		ID:          "data-protection",
		Name:        "Data Protection",
		Description: "Blocks writes to sensitive paths (.env, credentials, .ssh, /etc). Allows reads and other writes.",
		Category:    "compliance",
		Icon:        "shield",
		Rules: []TemplateRule{
			{
				Name:      "Deny writes to sensitive paths",
				ToolMatch: "write_file",
				Condition: `"path" in arguments && (string(arguments["path"]).startsWith("/etc") || string(arguments["path"]).contains(".env") || string(arguments["path"]).contains("credentials") || string(arguments["path"]).contains(".ssh"))`,
				Action:    ActionDeny,
				Priority:  100,
			},
			{
				Name:      "Allow read operations",
				ToolMatch: "*",
				Condition: "tool_name in ['read_file','list_directory','search_files','list_files','get_file_info']",
				Action:    ActionAllow,
				Priority:  90,
			},
			{
				Name:      "Allow other writes",
				ToolMatch: "write_file",
				Condition: "true",
				Action:    ActionAllow,
				Priority:  70,
			},
			{
				Name:      "Default allow",
				ToolMatch: "*",
				Condition: "true",
				Action:    ActionAllow,
				Priority:  1,
			},
		},
	}
}

func antiExfiltration() PolicyTemplate {
	return PolicyTemplate{
		ID:          "anti-exfiltration",
		Name:        "Anti-Exfiltration",
		Description: "Detects and blocks data exfiltration patterns: reading sensitive files followed by sending data externally.",
		Category:    "security",
		Icon:        "shield",
		Rules: []TemplateRule{
			{
				Name:      "Block send after file read",
				ToolMatch: "send_*",
				Condition: `session_sequence(session_action_history, "read_file", action_name)`,
				Action:    ActionDeny,
				Priority:  10,
			},
			{
				Name:      "Rate limit writes",
				ToolMatch: "write_*",
				Condition: `session_count_window(session_action_history, action_name, 60) > 50`,
				Action:    ActionDeny,
				Priority:  20,
			},
			{
				Name:      "Block rapid tool switching",
				ToolMatch: "*",
				Condition: `session_count(session_action_history, "write") > 100`,
				Action:    ActionDeny,
				Priority:  30,
			},
		},
	}
}
