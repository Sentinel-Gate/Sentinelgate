package transform

import (
	"testing"
)

func TestTransformRule_Validate_Valid(t *testing.T) {
	tests := []struct {
		name string
		rule TransformRule
	}{
		{
			name: "valid redact",
			rule: TransformRule{
				Name:      "redact-keys",
				ToolMatch: "*",
				Type:      TransformRedact,
				Config:    TransformConfig{Patterns: []string{`sk-[a-zA-Z0-9]{20,}`}},
			},
		},
		{
			name: "valid truncate by bytes",
			rule: TransformRule{
				Name:      "truncate-large",
				ToolMatch: "read_*",
				Type:      TransformTruncate,
				Config:    TransformConfig{MaxBytes: 1024},
			},
		},
		{
			name: "valid truncate by lines",
			rule: TransformRule{
				Name:      "truncate-lines",
				ToolMatch: "*",
				Type:      TransformTruncate,
				Config:    TransformConfig{MaxLines: 50},
			},
		},
		{
			name: "valid inject prepend",
			rule: TransformRule{
				Name:      "inject-warning",
				ToolMatch: "*",
				Type:      TransformInject,
				Config:    TransformConfig{Prepend: "[WARNING] This is a test environment."},
			},
		},
		{
			name: "valid inject append",
			rule: TransformRule{
				Name:      "inject-footer",
				ToolMatch: "*",
				Type:      TransformInject,
				Config:    TransformConfig{Append: "--- end of response ---"},
			},
		},
		{
			name: "valid dry_run",
			rule: TransformRule{
				Name:      "dry-run-all",
				ToolMatch: "write_*",
				Type:      TransformDryRun,
				Config:    TransformConfig{},
			},
		},
		{
			name: "valid mask",
			rule: TransformRule{
				Name:      "mask-tokens",
				ToolMatch: "*",
				Type:      TransformMask,
				Config:    TransformConfig{MaskPatterns: []string{`sk-[a-zA-Z0-9]+`}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.rule.Validate(); err != nil {
				t.Errorf("expected valid, got error: %v", err)
			}
		})
	}
}

func TestTransformRule_Validate_MissingName(t *testing.T) {
	rule := TransformRule{
		Name:      "",
		ToolMatch: "*",
		Type:      TransformRedact,
		Config:    TransformConfig{Patterns: []string{`test`}},
	}
	err := rule.Validate()
	if err == nil {
		t.Fatal("expected error for missing name")
	}
	if err.Error() != "transform rule name is required" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestTransformRule_Validate_MissingToolMatch(t *testing.T) {
	rule := TransformRule{
		Name:      "test",
		ToolMatch: "",
		Type:      TransformRedact,
		Config:    TransformConfig{Patterns: []string{`test`}},
	}
	err := rule.Validate()
	if err == nil {
		t.Fatal("expected error for missing tool_match")
	}
	if err.Error() != "transform rule tool_match is required" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestTransformRule_Validate_InvalidType(t *testing.T) {
	rule := TransformRule{
		Name:      "test",
		ToolMatch: "*",
		Type:      TransformType("bogus"),
		Config:    TransformConfig{},
	}
	err := rule.Validate()
	if err == nil {
		t.Fatal("expected error for invalid type")
	}
}

func TestTransformRule_Validate_RedactNoPatterns(t *testing.T) {
	rule := TransformRule{
		Name:      "test",
		ToolMatch: "*",
		Type:      TransformRedact,
		Config:    TransformConfig{},
	}
	err := rule.Validate()
	if err == nil {
		t.Fatal("expected error for redact with no patterns")
	}
}

func TestTransformRule_Validate_RedactBadRegex(t *testing.T) {
	rule := TransformRule{
		Name:      "test",
		ToolMatch: "*",
		Type:      TransformRedact,
		Config:    TransformConfig{Patterns: []string{`[invalid`}},
	}
	err := rule.Validate()
	if err == nil {
		t.Fatal("expected error for invalid regex pattern")
	}
}

func TestTransformRule_Validate_TruncateNoLimits(t *testing.T) {
	rule := TransformRule{
		Name:      "test",
		ToolMatch: "*",
		Type:      TransformTruncate,
		Config:    TransformConfig{},
	}
	err := rule.Validate()
	if err == nil {
		t.Fatal("expected error for truncate with no limits")
	}
}

func TestTransformRule_Validate_InjectEmpty(t *testing.T) {
	rule := TransformRule{
		Name:      "test",
		ToolMatch: "*",
		Type:      TransformInject,
		Config:    TransformConfig{},
	}
	err := rule.Validate()
	if err == nil {
		t.Fatal("expected error for inject with no prepend or append")
	}
}

func TestTransformRule_Validate_MaskNoPatterns(t *testing.T) {
	rule := TransformRule{
		Name:      "test",
		ToolMatch: "*",
		Type:      TransformMask,
		Config:    TransformConfig{},
	}
	err := rule.Validate()
	if err == nil {
		t.Fatal("expected error for mask with no patterns")
	}
}

func TestTransformRule_MatchesTool(t *testing.T) {
	tests := []struct {
		pattern  string
		tool     string
		expected bool
	}{
		{"*", "read_file", true},
		{"*", "write_file", true},
		{"read_*", "read_file", true},
		{"read_*", "write_file", false},
		{"read_file", "read_file", true},
		{"read_file", "write_file", false},
		{"file_*", "file_read", true},
		{"file_*", "file_write", true},
		{"file_*", "network_call", false},
		{"*_file", "read_file", true},
		{"*_file", "write_file", true},
		{"*_file", "read_dir", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.tool, func(t *testing.T) {
			rule := TransformRule{ToolMatch: tt.pattern}
			got := rule.MatchesTool(tt.tool)
			if got != tt.expected {
				t.Errorf("MatchesTool(%q) with pattern %q = %v, want %v",
					tt.tool, tt.pattern, got, tt.expected)
			}
		})
	}
}

func TestSortByPriority(t *testing.T) {
	rules := []TransformRule{
		{Name: "third", Priority: 30},
		{Name: "first", Priority: 10},
		{Name: "second", Priority: 20},
		{Name: "also-first", Priority: 10}, // same priority, stable sort preserves order
	}

	sorted := SortByPriority(rules)

	// Verify original is unchanged
	if rules[0].Name != "third" {
		t.Error("original slice was mutated")
	}

	expected := []string{"first", "also-first", "second", "third"}
	for i, name := range expected {
		if sorted[i].Name != name {
			t.Errorf("sorted[%d] = %q, want %q", i, sorted[i].Name, name)
		}
	}
}
