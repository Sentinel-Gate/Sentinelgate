package policy

import (
	"testing"
)

func TestAllTemplates_Count(t *testing.T) {
	templates := AllTemplates()
	if got := len(templates); got != 7 {
		t.Errorf("AllTemplates() returned %d templates, want 7", got)
	}
}

func TestAllTemplates_UniqueIDs(t *testing.T) {
	templates := AllTemplates()
	seen := make(map[string]bool, len(templates))
	for _, tmpl := range templates {
		if seen[tmpl.ID] {
			t.Errorf("duplicate template ID: %q", tmpl.ID)
		}
		seen[tmpl.ID] = true
	}
}

func TestAllTemplates_Fields(t *testing.T) {
	for _, tmpl := range AllTemplates() {
		t.Run(tmpl.ID, func(t *testing.T) {
			if tmpl.ID == "" {
				t.Error("ID is empty")
			}
			if tmpl.Name == "" {
				t.Error("Name is empty")
			}
			if tmpl.Description == "" {
				t.Error("Description is empty")
			}
			if tmpl.Category == "" {
				t.Error("Category is empty")
			}
			if tmpl.Icon == "" {
				t.Error("Icon is empty")
			}
			if len(tmpl.Rules) == 0 {
				t.Error("Rules is empty, want at least 1 rule")
			}
			for i, r := range tmpl.Rules {
				if r.Name == "" {
					t.Errorf("Rule[%d].Name is empty", i)
				}
				if r.ToolMatch == "" {
					t.Errorf("Rule[%d].ToolMatch is empty", i)
				}
				if r.Condition == "" {
					t.Errorf("Rule[%d].Condition is empty", i)
				}
				if r.Action != ActionAllow && r.Action != ActionDeny {
					t.Errorf("Rule[%d].Action = %q, want allow or deny", i, r.Action)
				}
				if r.Priority <= 0 {
					t.Errorf("Rule[%d].Priority = %d, want > 0", i, r.Priority)
				}
			}
		})
	}
}

func TestGetTemplate_Found(t *testing.T) {
	for _, tmpl := range AllTemplates() {
		t.Run(tmpl.ID, func(t *testing.T) {
			got, ok := GetTemplate(tmpl.ID)
			if !ok {
				t.Fatalf("GetTemplate(%q) not found", tmpl.ID)
			}
			if got.ID != tmpl.ID {
				t.Errorf("GetTemplate(%q).ID = %q", tmpl.ID, got.ID)
			}
			if got.Name != tmpl.Name {
				t.Errorf("GetTemplate(%q).Name = %q, want %q", tmpl.ID, got.Name, tmpl.Name)
			}
		})
	}
}

func TestGetTemplate_NotFound(t *testing.T) {
	_, ok := GetTemplate("nonexistent")
	if ok {
		t.Error("GetTemplate(\"nonexistent\") should return false")
	}
}

func TestAntiExfiltrationTemplate(t *testing.T) {
	tmpl, ok := GetTemplate("anti-exfiltration")
	if !ok {
		t.Fatal("anti-exfiltration template not found")
	}

	if tmpl.ID != "anti-exfiltration" {
		t.Errorf("ID = %q, want %q", tmpl.ID, "anti-exfiltration")
	}
	if tmpl.Category != "security" {
		t.Errorf("Category = %q, want %q", tmpl.Category, "security")
	}
	if len(tmpl.Rules) != 3 {
		t.Fatalf("Rules count = %d, want 3", len(tmpl.Rules))
	}

	// Verify ToPolicy produces a valid policy.
	p := tmpl.ToPolicy()
	if p == nil {
		t.Fatal("ToPolicy() returned nil")
	}
	if p.Name != "Anti-Exfiltration" {
		t.Errorf("ToPolicy().Name = %q, want %q", p.Name, "Anti-Exfiltration")
	}
	if !p.Enabled {
		t.Error("ToPolicy().Enabled should be true")
	}
	if len(p.Rules) != 3 {
		t.Fatalf("ToPolicy().Rules count = %d, want 3", len(p.Rules))
	}
}

func TestToPolicy(t *testing.T) {
	for _, tmpl := range AllTemplates() {
		t.Run(tmpl.ID, func(t *testing.T) {
			p := tmpl.ToPolicy()
			if p == nil {
				t.Fatal("ToPolicy() returned nil")
			}
			if p.Name != tmpl.Name {
				t.Errorf("ToPolicy().Name = %q, want %q", p.Name, tmpl.Name)
			}
			if p.Description != tmpl.Description {
				t.Errorf("ToPolicy().Description = %q, want %q", p.Description, tmpl.Description)
			}
			if !p.Enabled {
				t.Error("ToPolicy().Enabled should be true")
			}
			if len(p.Rules) != len(tmpl.Rules) {
				t.Fatalf("ToPolicy().Rules count = %d, want %d", len(p.Rules), len(tmpl.Rules))
			}
			// ID and timestamps should be zero (caller assigns).
			if p.ID != "" {
				t.Errorf("ToPolicy().ID = %q, want empty (caller assigns)", p.ID)
			}
			if !p.CreatedAt.IsZero() {
				t.Error("ToPolicy().CreatedAt should be zero")
			}
			// Every rule should have non-empty ToolMatch and Condition.
			for i, r := range p.Rules {
				if r.ToolMatch == "" {
					t.Errorf("Rule[%d].ToolMatch is empty", i)
				}
				if r.Condition == "" {
					t.Errorf("Rule[%d].Condition is empty", i)
				}
			}
		})
	}
}
