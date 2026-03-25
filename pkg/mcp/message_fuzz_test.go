package mcp

import (
	"encoding/json"
	"testing"
)

// FuzzRawID fuzzes Message.RawID() with arbitrary byte slices to ensure
// it never panics regardless of input. (Phase 6.1)
func FuzzRawID(f *testing.F) {
	// Seed corpus: various JSON payloads
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":null,"method":"tools/list"}`))
	f.Add([]byte(`{"jsonrpc":"2.0","method":"tools/list"}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":"str-id","method":"test"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`invalid`))
	f.Add([]byte(``))
	f.Add([]byte(`{"id":[]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		msg := &Message{Raw: data}
		// Must not panic
		result := msg.RawID()

		// If we got a non-nil result, it should be valid JSON
		if result != nil {
			if !json.Valid(result) {
				t.Errorf("RawID returned invalid JSON: %q", result)
			}
		}
	})
}

// FuzzExtractAPIKey fuzzes Message.ExtractAPIKey() via WrapMessage to ensure
// it never panics regardless of input. (Phase 6.3)
func FuzzExtractAPIKey(f *testing.F) {
	// Seed corpus
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{"apiKey":"test-key"}}}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"apiKey":"fallback"}}`))
	f.Add([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`invalid json`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, data []byte) {
		msg, err := WrapMessage(data, ClientToServer)
		if err != nil {
			return
		}
		// Must not panic
		_ = msg.ExtractAPIKey()
	})
}
