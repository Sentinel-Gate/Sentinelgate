package upstream

import (
	"errors"
	"testing"
	"time"
)

func TestUpstreamTypeConstants(t *testing.T) {
	if UpstreamTypeStdio != "stdio" {
		t.Errorf("UpstreamTypeStdio = %q, want %q", UpstreamTypeStdio, "stdio")
	}
	if UpstreamTypeHTTP != "http" {
		t.Errorf("UpstreamTypeHTTP = %q, want %q", UpstreamTypeHTTP, "http")
	}
}

func TestConnectionStatusConstants(t *testing.T) {
	tests := []struct {
		got  ConnectionStatus
		want string
	}{
		{StatusConnected, "connected"},
		{StatusDisconnected, "disconnected"},
		{StatusConnecting, "connecting"},
		{StatusError, "error"},
	}
	for _, tt := range tests {
		if string(tt.got) != tt.want {
			t.Errorf("ConnectionStatus = %q, want %q", tt.got, tt.want)
		}
	}
}

func TestUpstreamStruct(t *testing.T) {
	now := time.Now()
	u := Upstream{
		ID:        "abc-123",
		Name:      "my-server",
		Type:      UpstreamTypeStdio,
		Enabled:   true,
		Command:   "/usr/bin/mcp",
		Args:      []string{"--port", "8080"},
		Env:       map[string]string{"KEY": "value"},
		Status:    StatusConnected,
		ToolCount: 5,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if u.ID != "abc-123" {
		t.Errorf("ID = %q, want %q", u.ID, "abc-123")
	}
	if u.Name != "my-server" {
		t.Errorf("Name = %q, want %q", u.Name, "my-server")
	}
	if u.Type != UpstreamTypeStdio {
		t.Errorf("Type = %q, want %q", u.Type, UpstreamTypeStdio)
	}
	if !u.Enabled {
		t.Error("Enabled should be true")
	}
	if u.Command != "/usr/bin/mcp" {
		t.Errorf("Command = %q, want %q", u.Command, "/usr/bin/mcp")
	}
	if len(u.Args) != 2 {
		t.Fatalf("Args length = %d, want 2", len(u.Args))
	}
	if u.Env["KEY"] != "value" {
		t.Errorf("Env[KEY] = %q, want %q", u.Env["KEY"], "value")
	}
	if u.ToolCount != 5 {
		t.Errorf("ToolCount = %d, want 5", u.ToolCount)
	}
}

func TestUpstreamErrors(t *testing.T) {
	// Verify sentinel errors exist and have expected messages.
	if ErrUpstreamNotFound == nil {
		t.Fatal("ErrUpstreamNotFound should not be nil")
	}
	if ErrDuplicateUpstreamName == nil {
		t.Fatal("ErrDuplicateUpstreamName should not be nil")
	}

	if ErrUpstreamNotFound.Error() != "upstream not found" {
		t.Errorf("ErrUpstreamNotFound = %q, want %q", ErrUpstreamNotFound.Error(), "upstream not found")
	}
	if ErrDuplicateUpstreamName.Error() != "duplicate upstream name" {
		t.Errorf("ErrDuplicateUpstreamName = %q, want %q", ErrDuplicateUpstreamName.Error(), "duplicate upstream name")
	}

	// Verify they are distinct errors.
	if errors.Is(ErrUpstreamNotFound, ErrDuplicateUpstreamName) {
		t.Error("ErrUpstreamNotFound and ErrDuplicateUpstreamName should be distinct")
	}
}

func TestUpstreamValidateStdio(t *testing.T) {
	u := &Upstream{
		Name:    "valid-stdio",
		Type:    UpstreamTypeStdio,
		Command: "/usr/bin/mcp",
	}
	if err := u.Validate(); err != nil {
		t.Errorf("valid stdio upstream: unexpected error: %v", err)
	}

	// Missing command.
	u.Command = ""
	if err := u.Validate(); err == nil {
		t.Error("stdio upstream without command should fail validation")
	}
}

func TestUpstreamValidateHTTP(t *testing.T) {
	u := &Upstream{
		Name: "valid-http",
		Type: UpstreamTypeHTTP,
		URL:  "https://example.com/mcp",
	}
	if err := u.Validate(); err != nil {
		t.Errorf("valid http upstream: unexpected error: %v", err)
	}

	// Missing URL.
	u.URL = ""
	if err := u.Validate(); err == nil {
		t.Error("http upstream without URL should fail validation")
	}

	// Invalid URL.
	u.URL = "not-a-url"
	if err := u.Validate(); err == nil {
		t.Error("http upstream with invalid URL should fail validation")
	}

	// Disallowed scheme.
	u.URL = "ftp://example.com/mcp"
	if err := u.Validate(); err == nil {
		t.Error("http upstream with ftp scheme should fail validation")
	}
}

func TestUpstreamValidateNameRules(t *testing.T) {
	base := Upstream{
		Type:    UpstreamTypeStdio,
		Command: "/bin/true",
	}

	// Empty name.
	u := base
	u.Name = ""
	if err := u.Validate(); err == nil {
		t.Error("empty name should fail validation")
	}

	// Name with invalid characters.
	u = base
	u.Name = "bad<name>"
	if err := u.Validate(); err == nil {
		t.Error("name with angle brackets should fail validation")
	}

	// Valid name with allowed special chars.
	u = base
	u.Name = "My Server_v2-test"
	if err := u.Validate(); err != nil {
		t.Errorf("valid name with spaces, underscores, hyphens: unexpected error: %v", err)
	}
}

func TestUpstreamValidateInvalidType(t *testing.T) {
	u := &Upstream{
		Name: "bad-type",
		Type: UpstreamType("grpc"),
	}
	if err := u.Validate(); err == nil {
		t.Error("unknown upstream type should fail validation")
	}
}
