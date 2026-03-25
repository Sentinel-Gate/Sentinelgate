package redteam

import "time"

// AttackCategory classifies attack patterns.
type AttackCategory string

const (
	CategoryToolMisuse        AttackCategory = "tool_misuse"
	CategoryArgManipulation   AttackCategory = "argument_manipulation"
	CategoryPromptInjDirect   AttackCategory = "prompt_injection_direct"
	CategoryPromptInjIndirect AttackCategory = "prompt_injection_indirect"
	CategoryPermEscalation    AttackCategory = "permission_escalation"
	CategoryMultiStep         AttackCategory = "multi_step"
)

// AttackSeverity indicates how dangerous an attack pattern is.
type AttackSeverity string

const (
	SeverityCritical AttackSeverity = "critical"
	SeverityHigh     AttackSeverity = "high"
	SeverityMedium   AttackSeverity = "medium"
	SeverityLow      AttackSeverity = "low"
)

// AttackPattern defines a single attack to simulate against the current configuration.
type AttackPattern struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Category    AttackCategory         `json:"category"`
	Severity    AttackSeverity         `json:"severity"`
	ToolName    string                 `json:"tool_name"`
	Arguments   map[string]interface{} `json:"arguments"`
	Roles       []string               `json:"roles"`
	ActionType  string                 `json:"action_type"`
	Protocol    string                 `json:"protocol"`
	ExpectBlock bool                   `json:"expect_block"`
	Remediation *SuggestedRule         `json:"remediation,omitempty"`
}

// SuggestedRule is a CEL policy rule suggested to fix a vulnerability.
type SuggestedRule struct {
	Name      string `json:"name"`
	ToolMatch string `json:"tool_match"`
	Condition string `json:"condition"`
	Action    string `json:"action"`
	Priority  int    `json:"priority"`
}

// TestResult is the outcome of running a single attack pattern.
type TestResult struct {
	PatternID   string         `json:"pattern_id"`
	PatternName string         `json:"pattern_name"`
	Category    AttackCategory `json:"category"`
	Severity    AttackSeverity `json:"severity"`
	Description string         `json:"description"`
	Blocked     bool           `json:"blocked"`
	Method      string         `json:"method"`
	RuleID      string         `json:"rule_id,omitempty"`
	RuleName    string         `json:"rule_name,omitempty"`
	Reason      string         `json:"reason"`
	Explanation string         `json:"explanation,omitempty"`
	Remediation *SuggestedRule `json:"remediation,omitempty"`
}

// CategoryScore summarizes results for one attack category.
type CategoryScore struct {
	Category AttackCategory `json:"category"`
	Total    int            `json:"total"`
	Blocked  int            `json:"blocked"`
	Passed   int            `json:"passed"`
}

// Report is the full result of a red team test run.
type Report struct {
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	TargetID   string    `json:"target_identity"`
	Roles      []string  `json:"roles"`
	CorpusSize int       `json:"corpus_size"`
	DurationMs int64     `json:"duration_ms"`

	Scores       []CategoryScore `json:"scores"`
	TotalBlocked int             `json:"total_blocked"`
	TotalPassed  int             `json:"total_passed"`
	BlockRate    float64         `json:"block_rate"`

	Vulnerabilities []TestResult `json:"vulnerabilities"`
	AllResults      []TestResult `json:"all_results"`
}
