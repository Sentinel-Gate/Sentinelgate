package mcp

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

func TestEncodeDecodeRequest(t *testing.T) {
	// Create a request
	id, err := jsonrpc.MakeID(float64(1))
	if err != nil {
		t.Fatalf("MakeID failed: %v", err)
	}

	params := json.RawMessage(`{"name":"file_read","arguments":{"path":"/tmp/test.txt"}}`)
	req := &jsonrpc.Request{
		ID:     id,
		Method: "tools/call",
		Params: params,
	}

	// Encode
	encoded, err := EncodeMessage(req)
	if err != nil {
		t.Fatalf("EncodeMessage failed: %v", err)
	}

	// Decode
	decoded, err := DecodeMessage(encoded)
	if err != nil {
		t.Fatalf("DecodeMessage failed: %v", err)
	}

	// Verify it's a request
	decodedReq, ok := decoded.(*jsonrpc.Request)
	if !ok {
		t.Fatalf("expected *jsonrpc.Request, got %T", decoded)
	}

	if decodedReq.Method != "tools/call" {
		t.Errorf("expected method 'tools/call', got %q", decodedReq.Method)
	}
}

func TestEncodeDecodeResponse(t *testing.T) {
	// Create a response
	id, err := jsonrpc.MakeID(float64(1))
	if err != nil {
		t.Fatalf("MakeID failed: %v", err)
	}

	result := json.RawMessage(`{"content":"hello world"}`)
	resp := &jsonrpc.Response{
		ID:     id,
		Result: result,
	}

	// Encode
	encoded, err := EncodeMessage(resp)
	if err != nil {
		t.Fatalf("EncodeMessage failed: %v", err)
	}

	// Decode
	decoded, err := DecodeMessage(encoded)
	if err != nil {
		t.Fatalf("DecodeMessage failed: %v", err)
	}

	// Verify it's a response
	decodedResp, ok := decoded.(*jsonrpc.Response)
	if !ok {
		t.Fatalf("expected *jsonrpc.Response, got %T", decoded)
	}

	if decodedResp.Result == nil {
		t.Error("expected result to be set")
	}
}

func TestDecodeToolsCallRequest(t *testing.T) {
	// Raw JSON-RPC request for tools/call
	raw := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"file_read"}}`)

	decoded, err := DecodeMessage(raw)
	if err != nil {
		t.Fatalf("DecodeMessage failed: %v", err)
	}

	req, ok := decoded.(*jsonrpc.Request)
	if !ok {
		t.Fatalf("expected *jsonrpc.Request, got %T", decoded)
	}

	if req.Method != "tools/call" {
		t.Errorf("expected method 'tools/call', got %q", req.Method)
	}

	// Wrap and verify IsToolCall
	msg := &Message{
		Raw:       raw,
		Direction: ClientToServer,
		Decoded:   decoded,
		Timestamp: time.Now(),
	}

	if !msg.IsToolCall() {
		t.Error("expected IsToolCall() to return true")
	}
}

func TestDecodeMalformedJSON(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "not valid json",
			data: []byte(`{not valid`),
		},
		{
			name: "empty object",
			data: []byte(`{}`),
		},
		{
			name: "missing jsonrpc version",
			data: []byte(`{"id":1,"method":"test"}`),
		},
		{
			name: "wrong jsonrpc version",
			data: []byte(`{"jsonrpc":"1.0","id":1,"method":"test"}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeMessage(tt.data)
			if err == nil {
				t.Errorf("expected error for malformed JSON %q, got nil", tt.name)
			}
		})
	}
}

func TestWrapMessage(t *testing.T) {
	tests := []struct {
		name         string
		raw          []byte
		dir          Direction
		wantMethod   string
		wantRequest  bool
		wantToolCall bool
		wantErr      bool
	}{
		{
			name:         "tools/call request client to server",
			raw:          []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file"}}`),
			dir:          ClientToServer,
			wantMethod:   "tools/call",
			wantRequest:  true,
			wantToolCall: true,
			wantErr:      false,
		},
		{
			name:         "tools/list request",
			raw:          []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`),
			dir:          ClientToServer,
			wantMethod:   "tools/list",
			wantRequest:  true,
			wantToolCall: false,
			wantErr:      false,
		},
		{
			name:         "response server to client",
			raw:          []byte(`{"jsonrpc":"2.0","id":1,"result":{"content":"data"}}`),
			dir:          ServerToClient,
			wantMethod:   "",
			wantRequest:  false,
			wantToolCall: false,
			wantErr:      false,
		},
		{
			name:    "invalid json returns error",
			raw:     []byte(`{invalid`),
			dir:     ClientToServer,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := WrapMessage(tt.raw, tt.dir)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// Verify raw bytes preserved
			if string(msg.Raw) != string(tt.raw) {
				t.Errorf("raw bytes not preserved: got %q, want %q", msg.Raw, tt.raw)
			}

			// Verify direction
			if msg.Direction != tt.dir {
				t.Errorf("direction: got %v, want %v", msg.Direction, tt.dir)
			}

			// Verify timestamp is set
			if msg.Timestamp.IsZero() {
				t.Error("timestamp should be set")
			}

			// Verify method
			if msg.Method() != tt.wantMethod {
				t.Errorf("Method(): got %q, want %q", msg.Method(), tt.wantMethod)
			}

			// Verify IsRequest
			if msg.IsRequest() != tt.wantRequest {
				t.Errorf("IsRequest(): got %v, want %v", msg.IsRequest(), tt.wantRequest)
			}

			// Verify IsResponse is opposite of IsRequest (for valid messages)
			if msg.IsResponse() == tt.wantRequest {
				t.Errorf("IsResponse(): got %v, want %v", msg.IsResponse(), !tt.wantRequest)
			}

			// Verify IsToolCall
			if msg.IsToolCall() != tt.wantToolCall {
				t.Errorf("IsToolCall(): got %v, want %v", msg.IsToolCall(), tt.wantToolCall)
			}
		})
	}
}

func TestDirectionString(t *testing.T) {
	tests := []struct {
		dir  Direction
		want string
	}{
		{ClientToServer, "client->server"},
		{ServerToClient, "server->client"},
		{Direction(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.dir.String(); got != tt.want {
			t.Errorf("Direction(%d).String() = %q, want %q", tt.dir, got, tt.want)
		}
	}
}

func TestMessageAccessors(t *testing.T) {
	// Test Request() accessor
	reqRaw := []byte(`{"jsonrpc":"2.0","id":1,"method":"test"}`)
	reqMsg, err := WrapMessage(reqRaw, ClientToServer)
	if err != nil {
		t.Fatalf("WrapMessage failed: %v", err)
	}

	if reqMsg.Request() == nil {
		t.Error("Request() should return non-nil for request message")
	}
	if reqMsg.Response() != nil {
		t.Error("Response() should return nil for request message")
	}

	// Test Response() accessor
	respRaw := []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`)
	respMsg, err := WrapMessage(respRaw, ServerToClient)
	if err != nil {
		t.Fatalf("WrapMessage failed: %v", err)
	}

	if respMsg.Response() == nil {
		t.Error("Response() should return non-nil for response message")
	}
	if respMsg.Request() != nil {
		t.Error("Request() should return nil for response message")
	}
}

func TestMessageWithNilDecoded(t *testing.T) {
	msg := &Message{
		Raw:       []byte(`invalid`),
		Direction: ClientToServer,
		Decoded:   nil,
		Timestamp: time.Now(),
	}

	if msg.IsRequest() {
		t.Error("IsRequest() should return false for nil Decoded")
	}
	if msg.IsResponse() {
		t.Error("IsResponse() should return false for nil Decoded")
	}
	if msg.Method() != "" {
		t.Error("Method() should return empty string for nil Decoded")
	}
	if msg.IsToolCall() {
		t.Error("IsToolCall() should return false for nil Decoded")
	}
	if msg.Request() != nil {
		t.Error("Request() should return nil for nil Decoded")
	}
	if msg.Response() != nil {
		t.Error("Response() should return nil for nil Decoded")
	}
}
