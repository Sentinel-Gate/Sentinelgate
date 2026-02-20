package tool

import (
	"testing"
)

func TestClassifyTool_Critical(t *testing.T) {
	tests := []struct {
		name     string
		toolName string
		want     RiskLevel
	}{
		{"delete operation", "file_delete", RiskLevelCritical},
		{"remove operation", "database_remove", RiskLevelCritical},
		{"drop operation", "database_drop", RiskLevelCritical},
		{"destroy operation", "destroy_resource", RiskLevelCritical},
		{"execute operation", "execute_command", RiskLevelCritical},
		{"exec operation", "exec_script", RiskLevelCritical},
		{"shell operation", "shell_run", RiskLevelCritical},
		{"command operation", "run_command", RiskLevelCritical},
		{"admin operation", "admin_reset", RiskLevelCritical},
		{"sudo operation", "sudo_run", RiskLevelCritical},
		{"root operation", "root_access", RiskLevelCritical},
		{"truncate operation", "truncate_table", RiskLevelCritical},
		{"mixed case", "FILE_DELETE", RiskLevelCritical},
		{"camelCase", "fileDelete", RiskLevelCritical},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tool := Tool{Name: tt.toolName}
			got := ClassifyTool(tool)
			if got != tt.want {
				t.Errorf("ClassifyTool(%q) = %v, want %v", tt.toolName, got, tt.want)
			}
		})
	}
}

func TestClassifyTool_High(t *testing.T) {
	tests := []struct {
		name     string
		toolName string
		want     RiskLevel
	}{
		{"write operation", "file_write", RiskLevelHigh},
		{"create operation", "create_user", RiskLevelHigh},
		{"update operation", "update_config", RiskLevelHigh},
		{"modify operation", "modify_settings", RiskLevelHigh},
		{"send operation", "send_email", RiskLevelHigh},
		{"post operation", "post_message", RiskLevelHigh},
		{"upload operation", "upload_file", RiskLevelHigh},
		{"deploy operation", "deploy_app", RiskLevelHigh},
		{"install operation", "install_package", RiskLevelHigh},
		{"connect operation", "connect_db", RiskLevelHigh},
		{"put operation", "put_object", RiskLevelHigh},
		{"mixed case", "FILE_WRITE", RiskLevelHigh},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tool := Tool{Name: tt.toolName}
			got := ClassifyTool(tool)
			if got != tt.want {
				t.Errorf("ClassifyTool(%q) = %v, want %v", tt.toolName, got, tt.want)
			}
		})
	}
}

func TestClassifyTool_Medium(t *testing.T) {
	tests := []struct {
		name     string
		toolName string
		want     RiskLevel
	}{
		{"fetch operation", "fetch_data", RiskLevelMedium},
		{"download operation", "download_file", RiskLevelMedium},
		{"export operation", "export_report", RiskLevelMedium},
		{"query operation", "query_users", RiskLevelMedium},
		{"search operation", "search_users", RiskLevelMedium},
		{"get operation", "get_user_info", RiskLevelMedium},
		{"mixed case", "FETCH_DATA", RiskLevelMedium},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tool := Tool{Name: tt.toolName}
			got := ClassifyTool(tool)
			if got != tt.want {
				t.Errorf("ClassifyTool(%q) = %v, want %v", tt.toolName, got, tt.want)
			}
		})
	}
}

func TestClassifyTool_Low(t *testing.T) {
	tests := []struct {
		name     string
		toolName string
		want     RiskLevel
	}{
		{"list operation", "list_files", RiskLevelLow},
		{"status operation", "status_check", RiskLevelLow},
		{"echo operation", "echo", RiskLevelLow},
		{"help operation", "help", RiskLevelLow},
		{"version operation", "version", RiskLevelLow},
		{"info operation", "system_info", RiskLevelLow},
		{"ping operation", "ping", RiskLevelLow},
		{"health operation", "health_check", RiskLevelLow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tool := Tool{Name: tt.toolName}
			got := ClassifyTool(tool)
			if got != tt.want {
				t.Errorf("ClassifyTool(%q) = %v, want %v", tt.toolName, got, tt.want)
			}
		})
	}
}

func TestClassifyTool_PriorityOrder(t *testing.T) {
	// CRITICAL takes priority over HIGH
	t.Run("delete_and_create should be CRITICAL", func(t *testing.T) {
		tool := Tool{Name: "delete_and_create"}
		got := ClassifyTool(tool)
		if got != RiskLevelCritical {
			t.Errorf("ClassifyTool(%q) = %v, want %v (CRITICAL should win over HIGH)", tool.Name, got, RiskLevelCritical)
		}
	})

	// HIGH takes priority over MEDIUM
	t.Run("create_query should be HIGH", func(t *testing.T) {
		tool := Tool{Name: "create_query"}
		got := ClassifyTool(tool)
		if got != RiskLevelHigh {
			t.Errorf("ClassifyTool(%q) = %v, want %v (HIGH should win over MEDIUM)", tool.Name, got, RiskLevelHigh)
		}
	})

	// MEDIUM takes priority over LOW
	t.Run("list_and_get should be MEDIUM", func(t *testing.T) {
		tool := Tool{Name: "list_and_get"}
		got := ClassifyTool(tool)
		if got != RiskLevelMedium {
			t.Errorf("ClassifyTool(%q) = %v, want %v (MEDIUM should win over LOW)", tool.Name, got, RiskLevelMedium)
		}
	})
}

func TestClassifyTools_BulkClassification(t *testing.T) {
	input := []Tool{
		{Name: "file_delete"},
		{Name: "create_user"},
		{Name: "fetch_data"},
		{Name: "list_files"},
	}

	result := ClassifyTools(input)

	// Verify result has correct length
	if len(result) != len(input) {
		t.Fatalf("ClassifyTools returned %d tools, want %d", len(result), len(input))
	}

	// Verify each tool is classified correctly
	expected := []RiskLevel{
		RiskLevelCritical, // file_delete
		RiskLevelHigh,     // create_user
		RiskLevelMedium,   // fetch_data
		RiskLevelLow,      // list_files
	}

	for i, want := range expected {
		if result[i].RiskLevel != want {
			t.Errorf("result[%d].RiskLevel = %v, want %v", i, result[i].RiskLevel, want)
		}
	}
}

func TestClassifyTools_PreservesInput(t *testing.T) {
	input := []Tool{
		{Name: "file_delete", RiskLevel: ""},
		{Name: "list_files", RiskLevel: ""},
	}

	// Store original values
	origName0 := input[0].Name
	origName1 := input[1].Name
	origRisk0 := input[0].RiskLevel
	origRisk1 := input[1].RiskLevel

	result := ClassifyTools(input)

	// Verify input is not modified
	if input[0].Name != origName0 || input[0].RiskLevel != origRisk0 {
		t.Error("ClassifyTools modified input[0]")
	}
	if input[1].Name != origName1 || input[1].RiskLevel != origRisk1 {
		t.Error("ClassifyTools modified input[1]")
	}

	// Verify result is different slice
	if &result[0] == &input[0] {
		t.Error("ClassifyTools returned same slice as input")
	}

	// Verify result has classifications
	if result[0].RiskLevel != RiskLevelCritical {
		t.Errorf("result[0].RiskLevel = %v, want %v", result[0].RiskLevel, RiskLevelCritical)
	}
	if result[1].RiskLevel != RiskLevelLow {
		t.Errorf("result[1].RiskLevel = %v, want %v", result[1].RiskLevel, RiskLevelLow)
	}
}

func TestClassifyTools_EmptySlice(t *testing.T) {
	result := ClassifyTools([]Tool{})
	if result == nil {
		t.Error("ClassifyTools(empty) returned nil, want empty slice")
	}
	if len(result) != 0 {
		t.Errorf("ClassifyTools(empty) returned %d tools, want 0", len(result))
	}
}
