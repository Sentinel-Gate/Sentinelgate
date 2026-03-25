package proxy

import (
	"strings"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/upstream"
)

func FuzzToolNameResolution(f *testing.F) {
	// Seed corpus with representative tool names.
	f.Add("read_file")
	f.Add("desktop/read_file")
	f.Add("my-server/my_tool")
	f.Add("/leading_slash")
	f.Add("too/many/slashes/here")
	f.Add("")
	f.Add(strings.Repeat("a", 300)) // very long
	f.Add("server\x00name/tool")    // null byte
	f.Add("../../../etc/passwd")    // path traversal
	f.Add("server/tool\nname")      // newline injection

	f.Fuzz(func(t *testing.T, name string) {
		// sanitizeToolName must NOT panic for any input.
		_ = sanitizeToolName(name)

		// OriginalName must NOT panic for any input.
		_ = upstream.OriginalName(name)

		// OriginalName contract: result never has MORE slashes than input
		// (it strips at most the first prefix before "/").
		original := upstream.OriginalName(name)
		if strings.Count(original, "/") > strings.Count(name, "/") {
			t.Errorf("OriginalName(%q) = %q has more slashes than input", name, original)
		}

		// sanitizeToolName never returns a string longer than 256 chars.
		sanitized := sanitizeToolName(name)
		if len(sanitized) > 256 {
			t.Errorf("sanitizeToolName(%q) length = %d, want <= 256", name, len(sanitized))
		}

		// sanitizeToolName never contains control characters.
		for i := 0; i < len(sanitized); i++ {
			if sanitized[i] < 0x20 || sanitized[i] == 0x7f {
				t.Errorf("sanitizeToolName(%q) contains control char at index %d: 0x%02x", name, i, sanitized[i])
			}
		}
	})
}
