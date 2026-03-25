package redteam

import (
	"testing"
)

// allCategories is the exhaustive list of attack categories.
var allCategories = []AttackCategory{
	CategoryToolMisuse,
	CategoryArgManipulation,
	CategoryPromptInjDirect,
	CategoryPromptInjIndirect,
	CategoryPermEscalation,
	CategoryMultiStep,
}

func TestCorpusAllPatterns(t *testing.T) {
	patterns := Corpus()
	if len(patterns) == 0 {
		t.Fatal("Corpus() returned empty slice; expected at least one attack pattern")
	}
	t.Logf("Corpus contains %d attack patterns", len(patterns))
}

func TestCorpusHasAllCategories(t *testing.T) {
	patterns := Corpus()

	// Build a set of categories present in the corpus.
	seen := make(map[AttackCategory]int)
	for _, p := range patterns {
		seen[p.Category]++
	}

	for _, cat := range allCategories {
		count, ok := seen[cat]
		if !ok || count == 0 {
			t.Errorf("category %q has no patterns in the corpus", cat)
		}
	}
}

func TestCorpusPayloadsNonEmpty(t *testing.T) {
	patterns := Corpus()

	for _, p := range patterns {
		if p.ID == "" {
			t.Errorf("pattern has empty ID (Name=%q)", p.Name)
		}
		if p.Name == "" {
			t.Errorf("pattern %s has empty Name", p.ID)
		}
		if p.Description == "" {
			t.Errorf("pattern %s has empty Description", p.ID)
		}
		if p.Category == "" {
			t.Errorf("pattern %s has empty Category", p.ID)
		}
		if p.Severity == "" {
			t.Errorf("pattern %s has empty Severity", p.ID)
		}
		// ToolName may intentionally be empty for TM-004, skip that check.
		if p.ActionType == "" {
			t.Errorf("pattern %s has empty ActionType", p.ID)
		}
		if p.Protocol == "" {
			t.Errorf("pattern %s has empty Protocol", p.ID)
		}
		if len(p.Roles) == 0 {
			t.Errorf("pattern %s has no Roles", p.ID)
		}
	}
}

func TestCorpusCategoryFiltering(t *testing.T) {
	patterns := Corpus()

	for _, targetCat := range allCategories {
		var filtered []AttackPattern
		for _, p := range patterns {
			if p.Category == targetCat {
				filtered = append(filtered, p)
			}
		}

		if len(filtered) == 0 {
			t.Errorf("no patterns found for category %q", targetCat)
			continue
		}

		for _, p := range filtered {
			if p.Category != targetCat {
				t.Errorf("pattern %s has category %q, expected %q after filtering",
					p.ID, p.Category, targetCat)
			}
		}
		t.Logf("category %q: %d patterns", targetCat, len(filtered))
	}
}

func TestCorpusUniqueIDs(t *testing.T) {
	patterns := Corpus()
	seen := make(map[string]bool, len(patterns))
	for _, p := range patterns {
		if seen[p.ID] {
			t.Errorf("duplicate pattern ID: %s", p.ID)
		}
		seen[p.ID] = true
	}
}

func TestCorpusRemediationPresent(t *testing.T) {
	patterns := Corpus()
	for _, p := range patterns {
		if p.Remediation == nil {
			t.Errorf("pattern %s (%s) has nil Remediation", p.ID, p.Name)
			continue
		}
		if p.Remediation.Name == "" {
			t.Errorf("pattern %s remediation has empty Name", p.ID)
		}
		if p.Remediation.Condition == "" {
			t.Errorf("pattern %s remediation has empty Condition", p.ID)
		}
		if p.Remediation.Action == "" {
			t.Errorf("pattern %s remediation has empty Action", p.ID)
		}
	}
}

// TestCorpusRemediation_SpecificToolMatch verifies that all remediation rules
// use specific tool names (not broad wildcards like *_file or execute_*).
// Entries with ToolMatch "*" are intentional (content-based attacks that match any tool).
func TestCorpusRemediation_SpecificToolMatch(t *testing.T) {
	patterns := Corpus()

	// All entries that must have a specific tool name
	specifics := map[string]string{
		"TM-001": "execute_command",
		"TM-003": "delete_file",
		"TM-005": "sampling_createMessage",
		"TM-006": "write_file",
		"TM-007": "admin_reset_config",
		"AM-001": "execute_command",
		"AM-002": "read_file",
		"AM-003": "query_db",
		"AM-004": "execute_command",
		"AM-005": "read_file",
		"AM-006": "fetch_url",
		"AM-007": "render_template",
		"PE-001": "update_profile",
		"PE-002": "manage_user",
		"PE-003": "set_config",
		"MS-001": "execute_command",
		"MS-002": "send_email",
	}

	// Entries that must remain "*" (content-based patterns matching any tool)
	wildcards := map[string]bool{
		"TM-002": true, "TM-004": true,
		"PI-001": true, "PI-002": true, "PI-003": true, "PI-004": true, "PI-005": true,
		"IPI-001": true, "IPI-002": true, "IPI-003": true, "IPI-004": true, "IPI-005": true,
		"PE-004": true,
	}

	for _, p := range patterns {
		if p.Remediation == nil {
			continue
		}
		if expected, ok := specifics[p.ID]; ok {
			if p.Remediation.ToolMatch != expected {
				t.Errorf("pattern %s (%s): Remediation.ToolMatch = %q, want specific %q",
					p.ID, p.Name, p.Remediation.ToolMatch, expected)
			}
		}
		if wildcards[p.ID] {
			if p.Remediation.ToolMatch != "*" {
				t.Errorf("pattern %s (%s): Remediation.ToolMatch = %q, want intentional wildcard %q",
					p.ID, p.Name, p.Remediation.ToolMatch, "*")
			}
		}
	}
}
