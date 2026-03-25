package mcp

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestDecodeMessage_IDNullVsAbsentVsEmpty verifies that RawID() correctly
// distinguishes between id:null (explicit null), absent id (notification),
// and id:"" (empty string). These are semantically different in JSON-RPC 2.0.
func TestDecodeMessage_IDNullVsAbsentVsEmpty(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantRawID string // expected RawID() as string; "nil" means nil
	}{
		{
			name:      "id explicitly null",
			input:     `{"jsonrpc":"2.0","id":null,"method":"tools/list"}`,
			wantRawID: "null",
		},
		{
			name:      "id absent (notification)",
			input:     `{"jsonrpc":"2.0","method":"tools/list"}`,
			wantRawID: "nil",
		},
		{
			name:      "id empty string",
			input:     `{"jsonrpc":"2.0","id":"","method":"tools/list"}`,
			wantRawID: `""`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := []byte(tt.input)

			// DecodeMessage may return an error for some edge cases (e.g. id:null
			// might be rejected by the SDK). We only care that it doesn't panic.
			decoded, _ := DecodeMessage(raw)

			// Build a Message to test RawID()
			msg := &Message{
				Raw:       raw,
				Direction: ClientToServer,
				Decoded:   decoded,
				Timestamp: time.Now(),
			}

			got := msg.RawID()

			if tt.wantRawID == "nil" {
				if got != nil {
					t.Errorf("RawID() = %s, want nil", string(got))
				}
			} else {
				if got == nil {
					t.Fatalf("RawID() = nil, want %s", tt.wantRawID)
				}
				if string(got) != tt.wantRawID {
					t.Errorf("RawID() = %s, want %s", string(got), tt.wantRawID)
				}
			}
		})
	}
}

// TestDecodeMessage_InvalidJSONRPCVersion verifies that DecodeMessage does not
// panic when given an invalid or missing jsonrpc version. These should return
// an error (the SDK rejects non-"2.0" versions).
func TestDecodeMessage_InvalidJSONRPCVersion(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "jsonrpc version 1.0",
			input: `{"jsonrpc":"1.0","id":1,"method":"tools/list"}`,
		},
		{
			name:  "jsonrpc version empty string",
			input: `{"jsonrpc":"","id":1,"method":"tools/list"}`,
		},
		{
			name:  "jsonrpc field missing entirely",
			input: `{"id":1,"method":"tools/list"}`,
		},
		{
			name:  "jsonrpc version 3.0",
			input: `{"jsonrpc":"3.0","id":1,"method":"tools/list"}`,
		},
		{
			name:  "jsonrpc as number",
			input: `{"jsonrpc":2.0,"id":1,"method":"tools/list"}`,
		},
		{
			name:  "jsonrpc as null",
			input: `{"jsonrpc":null,"id":1,"method":"tools/list"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Must not panic. Error return is expected for invalid versions.
			_, err := DecodeMessage([]byte(tt.input))
			if err == nil {
				t.Errorf("DecodeMessage accepted invalid jsonrpc version in %q — expected error", tt.name)
			}
		})
	}
}

// TestDecodeMessage_MethodEdgeCases tests that DecodeMessage handles unusual
// method values without panicking. Method() should return the raw string
// as decoded by the SDK.
func TestDecodeMessage_MethodEdgeCases(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantMethod string
		wantErr    bool
	}{
		{
			name:       "empty method",
			input:      `{"jsonrpc":"2.0","id":1,"method":""}`,
			wantMethod: "",
			wantErr:    false,
		},
		{
			name:       "method with leading/trailing spaces",
			input:      `{"jsonrpc":"2.0","id":1,"method":" tools/list "}`,
			wantMethod: " tools/list ",
			wantErr:    false,
		},
		{
			name:       "method with null byte",
			input:      "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\\u0000\"}",
			wantMethod: "tools/list\x00",
			wantErr:    false,
		},
		{
			name:       "method with unicode",
			input:      `{"jsonrpc":"2.0","id":1,"method":"tools/call\u2028"}`,
			wantMethod: "tools/call\u2028",
			wantErr:    false,
		},
		{
			name:    "method as number instead of string",
			input:   `{"jsonrpc":"2.0","id":1,"method":42}`,
			wantErr: true,
		},
		{
			name:    "method as null",
			input:   `{"jsonrpc":"2.0","id":1,"method":null}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decoded, err := DecodeMessage([]byte(tt.input))
			if tt.wantErr {
				// Must not panic; error is expected for invalid method types.
				if err == nil {
					t.Errorf("DecodeMessage accepted edge-case method in %q — expected error", tt.name)
				}
				return
			}
			if err != nil {
				t.Fatalf("DecodeMessage returned unexpected error: %v", err)
			}

			msg := &Message{
				Raw:       []byte(tt.input),
				Direction: ClientToServer,
				Decoded:   decoded,
				Timestamp: time.Now(),
			}

			if got := msg.Method(); got != tt.wantMethod {
				t.Errorf("Method() = %q, want %q", got, tt.wantMethod)
			}
		})
	}
}

// TestDecodeMessage_TopLevelArray verifies that a JSON-RPC batch request
// (top-level JSON array) is rejected by DecodeMessage without panicking.
// JSON-RPC 2.0 batch is not supported by the MCP protocol.
func TestDecodeMessage_TopLevelArray(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "single-element batch array",
			input: `[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]`,
		},
		{
			name:  "multi-element batch array",
			input: `[{"jsonrpc":"2.0","id":1,"method":"tools/list"},{"jsonrpc":"2.0","id":2,"method":"tools/call"}]`,
		},
		{
			name:  "empty array",
			input: `[]`,
		},
		{
			name:  "array of primitives",
			input: `[1, 2, 3]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeMessage([]byte(tt.input))
			if err == nil {
				t.Error("DecodeMessage should return error for top-level array (batch not supported)")
			}
		})
	}
}

// TestDecodeMessage_InvalidUTF8 verifies that DecodeMessage handles invalid
// UTF-8 bytes without crashing. Go's json.Unmarshal may accept some invalid
// sequences — we verify no downstream panic occurs.
func TestDecodeMessage_InvalidUTF8(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "invalid UTF-8 in method",
			input: []byte("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/\xff\xfe\"}"),
		},
		{
			name:  "invalid UTF-8 in string value",
			input: []byte("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\",\"params\":{\"name\":\"\xff\"}}"),
		},
		{
			name:  "lone continuation byte",
			input: []byte("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"\x80test\"}"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Must not panic — error return is acceptable
			decoded, err := DecodeMessage(tt.input)
			if err != nil {
				return // error is fine
			}

			// If it decoded successfully, verify no crash accessing the message
			msg := &Message{
				Raw:       tt.input,
				Direction: ClientToServer,
				Decoded:   decoded,
				Timestamp: time.Now(),
			}

			// Exercise all accessors — none should panic
			_ = msg.Method()
			_ = msg.IsRequest()
			_ = msg.IsResponse()
			_ = msg.IsToolCall()
			_ = msg.Request()
			_ = msg.Response()
			_ = msg.RawID()
			_ = msg.ExtractAPIKey()
		})
	}
}

// TestDecodeMessage_EmptyAndWhitespace verifies that DecodeMessage returns
// an error (not a panic) for empty input and whitespace-only input.
func TestDecodeMessage_EmptyAndWhitespace(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{name: "empty bytes", input: []byte("")},
		{name: "spaces only", input: []byte("   ")},
		{name: "newlines only", input: []byte("\n\n\n")},
		{name: "tab only", input: []byte("\t")},
		{name: "mixed whitespace", input: []byte(" \t\n\r ")},
		{name: "nil input", input: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeMessage(tt.input)
			if err == nil {
				t.Errorf("DecodeMessage(%q) should return error for empty/whitespace input", string(tt.input))
			}
		})
	}
}

// TestDecodeMessage_TruncatedJSON verifies that DecodeMessage returns an error
// (not a panic) for truncated JSON input.
func TestDecodeMessage_TruncatedJSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "truncated mid-key",
			input: `{"jsonrpc":"2.0","id":1,"met`,
		},
		{
			name:  "truncated mid-value",
			input: `{"jsonrpc":"2.0","id":1,"method":"tools/li`,
		},
		{
			name:  "truncated after colon",
			input: `{"jsonrpc":"2.0","method":`,
		},
		{
			name:  "opening brace only",
			input: `{`,
		},
		{
			name:  "truncated string",
			input: `{"jsonrpc":"2.0","method":"tools/list`,
		},
		{
			name:  "truncated after comma",
			input: `{"jsonrpc":"2.0",`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeMessage([]byte(tt.input))
			if err == nil {
				t.Errorf("DecodeMessage should return error for truncated JSON: %q", tt.input)
			}
		})
	}
}

// TestDecodeMessage_RawID_EdgeCases verifies RawID() with additional edge-case
// ID values: numeric types, large numbers, boolean, object, array.
func TestDecodeMessage_RawID_EdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		wantRawID string // expected string from RawID(), "nil" for nil
	}{
		{
			name:      "integer id",
			raw:       `{"jsonrpc":"2.0","id":42,"method":"test"}`,
			wantRawID: "42",
		},
		{
			name:      "string id",
			raw:       `{"jsonrpc":"2.0","id":"req-001","method":"test"}`,
			wantRawID: `"req-001"`,
		},
		{
			name:      "float id",
			raw:       `{"jsonrpc":"2.0","id":1.5,"method":"test"}`,
			wantRawID: "1.5",
		},
		{
			name:      "zero id",
			raw:       `{"jsonrpc":"2.0","id":0,"method":"test"}`,
			wantRawID: "0",
		},
		{
			name:      "negative id",
			raw:       `{"jsonrpc":"2.0","id":-1,"method":"test"}`,
			wantRawID: "-1",
		},
		{
			name:      "very large number id",
			raw:       `{"jsonrpc":"2.0","id":999999999999999999,"method":"test"}`,
			wantRawID: "999999999999999999",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := &Message{
				Raw:       []byte(tt.raw),
				Direction: ClientToServer,
				Timestamp: time.Now(),
			}

			got := msg.RawID()

			if tt.wantRawID == "nil" {
				if got != nil {
					t.Errorf("RawID() = %s, want nil", string(got))
				}
			} else {
				if got == nil {
					t.Fatalf("RawID() = nil, want %s", tt.wantRawID)
				}
				if string(got) != tt.wantRawID {
					t.Errorf("RawID() = %s, want %s", string(got), tt.wantRawID)
				}
			}
		})
	}
}

// TestDecodeMessage_RawID_NilRaw verifies RawID() returns nil when Raw is nil.
func TestDecodeMessage_RawID_NilRaw(t *testing.T) {
	msg := &Message{
		Raw:       nil,
		Direction: ClientToServer,
		Timestamp: time.Now(),
	}

	if got := msg.RawID(); got != nil {
		t.Errorf("RawID() = %s, want nil for nil Raw", string(got))
	}
}

// TestDecodeMessage_RawID_InvalidJSON verifies RawID() returns nil for invalid JSON.
func TestDecodeMessage_RawID_InvalidJSON(t *testing.T) {
	msg := &Message{
		Raw:       []byte(`{not valid json`),
		Direction: ClientToServer,
		Timestamp: time.Now(),
	}

	if got := msg.RawID(); got != nil {
		t.Errorf("RawID() = %s, want nil for invalid JSON", string(got))
	}
}

// TestDecodeMessage_WrapMessage_PreservesIDSemantics verifies that the full
// WrapMessage + RawID() pipeline preserves the distinction between different
// ID representations.
func TestDecodeMessage_WrapMessage_PreservesIDSemantics(t *testing.T) {
	// Verify that a numeric ID round-trips correctly through WrapMessage
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	msg, err := WrapMessage(raw, ClientToServer)
	if err != nil {
		t.Fatalf("WrapMessage failed: %v", err)
	}

	gotID := msg.RawID()
	if gotID == nil {
		t.Fatal("RawID() returned nil for message with id:1")
	}

	// Must be the number 1, not a string "1"
	var num json.Number
	if err := json.Unmarshal(gotID, &num); err != nil {
		t.Fatalf("RawID() is not a valid JSON number: %s", string(gotID))
	}
	if num.String() != "1" {
		t.Errorf("RawID() decoded to %s, want 1", num.String())
	}
}

// TestDecodeMessage_OversizedPayload (1A.4) verifies that DecodeMessage handles a
// very large payload without panicking. The bufio.Scanner in upstream_manager has a
// 1MB buffer limit, but DecodeMessage itself works with raw bytes and JSON parsing
// has no inherent size limit.
func TestDecodeMessage_OversizedPayload(t *testing.T) {
	// Create 2MB of data as a JSON string value
	bigStr := strings.Repeat("A", 2*1024*1024)
	input := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"data":"%s"}}`, bigStr)

	// DecodeMessage must not panic on oversized input
	decoded, err := DecodeMessage([]byte(input))
	if err != nil {
		t.Logf("DecodeMessage returned error for 2MB payload (expected): %v", err)
		return
	}

	// If it succeeded, verify accessors don't panic
	msg := &Message{Raw: []byte(input), Direction: ClientToServer, Decoded: decoded, Timestamp: time.Now()}
	_ = msg.Method()
	_ = msg.RawID()
	_ = msg.IsToolCall()

	t.Log("DecodeMessage accepted 2MB payload — note: bufio.Scanner in upstream_manager caps at 1MB")
}
