package proxy

import (
	"strings"
	"testing"
)

// FuzzToolNameRouting (6.4) fuzzes the ToolCacheReader.GetTool path
// that handleToolsCall relies on. The goal is to ensure that no tool
// name input causes a panic in the lookup or the surrounding logic.
func FuzzToolNameRouting(f *testing.F) {
	// Seed corpus: normal names, edge cases, adversarial inputs.
	f.Add("read_file")
	f.Add("write_file")
	f.Add("")
	f.Add("../admin/secret")
	f.Add("tool\x00name")
	f.Add(strings.Repeat("a", 100000))
	f.Add("tool with spaces")
	f.Add("<script>alert(1)</script>")
	f.Add("tool/sub/path")
	f.Add("tool\nname")
	f.Add("tool\rname")
	f.Add("tool\t\tname")
	f.Add("../../etc/passwd")
	f.Add("{\"name\":\"injected\"}")
	f.Add("tool%00name")
	f.Add(strings.Repeat("\x00", 1000))
	f.Add("SELECT * FROM tools")
	f.Add("tool\u200Bname") // zero-width space

	f.Fuzz(func(t *testing.T, toolName string) {
		// Build a cache with a few well-known tools.
		cache := newMockToolCacheReader(
			&RoutableTool{Name: "read_file", UpstreamID: "upstream-1", Description: "Reads a file"},
			&RoutableTool{Name: "write_file", UpstreamID: "upstream-1", Description: "Writes a file"},
			&RoutableTool{Name: "search", UpstreamID: "upstream-2", Description: "Searches"},
		)

		// GetTool must not panic with any input.
		tool, found := cache.GetTool(toolName)

		// If found, it must be one of the known tools.
		if found {
			if tool == nil {
				t.Fatal("GetTool returned found=true but tool is nil")
			}
			switch tool.Name {
			case "read_file", "write_file", "search":
				// expected
			default:
				t.Fatalf("GetTool returned unknown tool: %q", tool.Name)
			}
		}

		// GetAllTools must not panic.
		all := cache.GetAllTools()
		if len(all) != 3 {
			t.Fatalf("expected 3 tools, got %d", len(all))
		}
	})
}
