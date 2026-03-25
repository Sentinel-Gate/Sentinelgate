package service

import (
	"log/slog"
	"testing"
)

func TestNamespace_Disabled(t *testing.T) {
	svc := NewNamespaceService(slog.Default())
	// Disabled = all visible
	if !svc.IsToolVisible("anything", []string{"user"}) {
		t.Error("disabled should allow all tools")
	}
}

func TestNamespace_WhitelistMode(t *testing.T) {
	svc := NewNamespaceService(slog.Default())
	svc.SetConfig(NamespaceConfig{
		Enabled: true,
		Rules: map[string]*NamespaceRule{
			"marketing": {VisibleTools: []string{"search", "read_file", "analytics_*"}},
		},
	})

	tests := []struct {
		tool    string
		roles   []string
		visible bool
	}{
		{"search", []string{"marketing"}, true},
		{"read_file", []string{"marketing"}, true},
		{"analytics_report", []string{"marketing"}, true},    // glob match
		{"delete_file", []string{"marketing"}, false},         // not in whitelist
		{"query_db", []string{"marketing"}, false},            // not in whitelist
		{"delete_file", []string{"admin"}, false},             // M-10: admin has no rule = deny-by-default
		{"search", []string{"marketing", "admin"}, true},      // marketing whitelist includes search
	}

	for _, tt := range tests {
		got := svc.IsToolVisible(tt.tool, tt.roles)
		if got != tt.visible {
			t.Errorf("IsToolVisible(%q, %v) = %v, want %v", tt.tool, tt.roles, got, tt.visible)
		}
	}
}

func TestNamespace_BlacklistMode(t *testing.T) {
	svc := NewNamespaceService(slog.Default())
	svc.SetConfig(NamespaceConfig{
		Enabled: true,
		Rules: map[string]*NamespaceRule{
			"intern": {HiddenTools: []string{"delete_*", "exec_command"}},
		},
	})

	tests := []struct {
		tool    string
		roles   []string
		visible bool
	}{
		{"read_file", []string{"intern"}, true},
		{"search", []string{"intern"}, true},
		{"delete_file", []string{"intern"}, false},     // hidden by glob
		{"delete_db", []string{"intern"}, false},        // hidden by glob
		{"exec_command", []string{"intern"}, false},     // hidden exact
		{"exec_other", []string{"intern"}, true},        // not hidden
	}

	for _, tt := range tests {
		got := svc.IsToolVisible(tt.tool, tt.roles)
		if got != tt.visible {
			t.Errorf("IsToolVisible(%q, %v) = %v, want %v", tt.tool, tt.roles, got, tt.visible)
		}
	}
}

func TestNamespace_MultiRole(t *testing.T) {
	svc := NewNamespaceService(slog.Default())
	svc.SetConfig(NamespaceConfig{
		Enabled: true,
		Rules: map[string]*NamespaceRule{
			"reader":  {VisibleTools: []string{"read_*"}},
			"writer":  {VisibleTools: []string{"write_*"}},
		},
	})

	// reader+writer can see both
	if !svc.IsToolVisible("read_file", []string{"reader", "writer"}) {
		t.Error("reader+writer should see read_file")
	}
	if !svc.IsToolVisible("write_file", []string{"reader", "writer"}) {
		t.Error("reader+writer should see write_file")
	}
	// reader alone can't write
	if svc.IsToolVisible("write_file", []string{"reader"}) {
		t.Error("reader alone should not see write_file")
	}
}

func TestNamespace_FilterTools(t *testing.T) {
	svc := NewNamespaceService(slog.Default())
	svc.SetConfig(NamespaceConfig{
		Enabled: true,
		Rules: map[string]*NamespaceRule{
			"limited": {VisibleTools: []string{"read_file", "search"}},
		},
	})

	all := []string{"read_file", "write_file", "search", "delete_db", "exec_cmd"}
	got := svc.FilterTools(all, []string{"limited"})

	if len(got) != 2 {
		t.Fatalf("expected 2 visible tools, got %d: %v", len(got), got)
	}
}

func TestNamespace_EmptyRule(t *testing.T) {
	svc := NewNamespaceService(slog.Default())
	svc.SetConfig(NamespaceConfig{
		Enabled: true,
		Rules: map[string]*NamespaceRule{
			"open": {}, // empty rule = all visible
		},
	})

	if !svc.IsToolVisible("anything", []string{"open"}) {
		t.Error("empty rule should allow all")
	}
}

func TestNamespace_WildcardPattern(t *testing.T) {
	svc := NewNamespaceService(slog.Default())
	svc.SetConfig(NamespaceConfig{
		Enabled: true,
		Rules: map[string]*NamespaceRule{
			"all-access": {VisibleTools: []string{"*"}},
		},
	})

	if !svc.IsToolVisible("anything", []string{"all-access"}) {
		t.Error("wildcard * should match all")
	}
}

func TestNamespace_ConfigGetSet(t *testing.T) {
	svc := NewNamespaceService(slog.Default())

	cfg := svc.Config()
	if cfg.Enabled {
		t.Error("default should be disabled")
	}

	svc.SetConfig(NamespaceConfig{
		Enabled: true,
		Rules: map[string]*NamespaceRule{
			"test": {VisibleTools: []string{"a"}},
		},
	})

	cfg = svc.Config()
	if !cfg.Enabled {
		t.Error("should be enabled after set")
	}
	if len(cfg.Rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(cfg.Rules))
	}
}

func TestMatchToolPattern(t *testing.T) {
	tests := []struct {
		pattern, tool string
		match         bool
	}{
		{"read_file", "read_file", true},
		{"read_file", "write_file", false},
		{"read_*", "read_file", true},
		{"read_*", "read_dir", true},
		{"read_*", "write_file", false},
		{"*", "anything", true},
		{"", "", true},
		{"a", "ab", false},
	}
	for _, tt := range tests {
		if got := matchToolPattern(tt.pattern, tt.tool); got != tt.match {
			t.Errorf("matchToolPattern(%q, %q) = %v, want %v", tt.pattern, tt.tool, got, tt.match)
		}
	}
}
