package action

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestHTTPNormalizer_Normalize_GETRequest(t *testing.T) {
	normalizer := NewHTTPNormalizer()
	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/users?page=1&limit=10", nil)

	action, err := normalizer.Normalize(context.Background(), req)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	// WHAT
	if action.Type != ActionHTTPRequest {
		t.Errorf("Type = %q, want %q", action.Type, ActionHTTPRequest)
	}
	if action.Name != "GET" {
		t.Errorf("Name = %q, want %q", action.Name, "GET")
	}

	// WHERE - Destination
	if action.Destination.Domain != "api.example.com" {
		t.Errorf("Destination.Domain = %q, want %q", action.Destination.Domain, "api.example.com")
	}
	if action.Destination.Port != 80 {
		t.Errorf("Destination.Port = %d, want 80", action.Destination.Port)
	}
	if action.Destination.Scheme != "http" {
		t.Errorf("Destination.Scheme = %q, want %q", action.Destination.Scheme, "http")
	}
	if action.Destination.Path != "/users" {
		t.Errorf("Destination.Path = %q, want %q", action.Destination.Path, "/users")
	}
	if !strings.Contains(action.Destination.URL, "api.example.com") {
		t.Errorf("Destination.URL = %q, should contain host", action.Destination.URL)
	}

	// Arguments - query params
	if action.Arguments["page"] != "1" {
		t.Errorf("Arguments[page] = %v, want %q", action.Arguments["page"], "1")
	}
	if action.Arguments["limit"] != "10" {
		t.Errorf("Arguments[limit] = %v, want %q", action.Arguments["limit"], "10")
	}

	// HOW
	if action.Protocol != "http" {
		t.Errorf("Protocol = %q, want %q", action.Protocol, "http")
	}
	if action.Gateway != "http-gateway" {
		t.Errorf("Gateway = %q, want %q", action.Gateway, "http-gateway")
	}

	// CONTEXT
	if action.RequestTime.IsZero() {
		t.Error("RequestTime should not be zero")
	}

	// INTERNAL
	if action.OriginalMessage != req {
		t.Error("OriginalMessage should be the original *http.Request")
	}
}

func TestHTTPNormalizer_Normalize_POSTJSONRequest(t *testing.T) {
	normalizer := NewHTTPNormalizer()
	body := `{"name":"test-tool","enabled":true}`
	req := httptest.NewRequest(http.MethodPost, "http://api.example.com/tools", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	action, err := normalizer.Normalize(context.Background(), req)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if action.Name != "POST" {
		t.Errorf("Name = %q, want %q", action.Name, "POST")
	}

	// Body parsed into Arguments
	if action.Arguments["name"] != "test-tool" {
		t.Errorf("Arguments[name] = %v, want %q", action.Arguments["name"], "test-tool")
	}
	if action.Arguments["enabled"] != true {
		t.Errorf("Arguments[enabled] = %v, want true", action.Arguments["enabled"])
	}

	// Metadata
	if action.Metadata["content_type"] != "application/json" {
		t.Errorf("Metadata[content_type] = %v, want %q", action.Metadata["content_type"], "application/json")
	}
}

func TestHTTPNormalizer_Normalize_POSTFormRequest(t *testing.T) {
	normalizer := NewHTTPNormalizer()
	formData := url.Values{
		"username": {"admin"},
		"password": {"secret123"},
	}
	req := httptest.NewRequest(http.MethodPost, "http://example.com/login", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	action, err := normalizer.Normalize(context.Background(), req)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if action.Arguments["username"] != "admin" {
		t.Errorf("Arguments[username] = %v, want %q", action.Arguments["username"], "admin")
	}
	if action.Arguments["password"] != "secret123" {
		t.Errorf("Arguments[password] = %v, want %q", action.Arguments["password"], "secret123")
	}
}

func TestHTTPNormalizer_Normalize_CustomPort(t *testing.T) {
	normalizer := NewHTTPNormalizer()
	req := httptest.NewRequest(http.MethodGet, "http://localhost:9090/api/status", nil)

	action, err := normalizer.Normalize(context.Background(), req)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if action.Destination.Port != 9090 {
		t.Errorf("Destination.Port = %d, want 9090", action.Destination.Port)
	}
	if action.Destination.Domain != "localhost" {
		t.Errorf("Destination.Domain = %q, want %q", action.Destination.Domain, "localhost")
	}
}

func TestHTTPNormalizer_Normalize_DefaultPorts(t *testing.T) {
	normalizer := NewHTTPNormalizer()

	tests := []struct {
		name     string
		url      string
		wantPort int
	}{
		{"http default", "http://example.com/path", 80},
		{"https default", "https://secure.example.com/path", 443},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.url, nil)
			action, err := normalizer.Normalize(context.Background(), req)
			if err != nil {
				t.Fatalf("Normalize() error = %v", err)
			}
			if action.Destination.Port != tt.wantPort {
				t.Errorf("Destination.Port = %d, want %d", action.Destination.Port, tt.wantPort)
			}
		})
	}
}

func TestHTTPNormalizer_Normalize_RequestIDFromHeader(t *testing.T) {
	normalizer := NewHTTPNormalizer()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("X-Request-Id", "custom-request-id-123")

	action, err := normalizer.Normalize(context.Background(), req)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if action.RequestID != "custom-request-id-123" {
		t.Errorf("RequestID = %q, want %q", action.RequestID, "custom-request-id-123")
	}
}

func TestHTTPNormalizer_Normalize_RequestIDGenerated(t *testing.T) {
	normalizer := NewHTTPNormalizer()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	// No X-Request-Id header

	action, err := normalizer.Normalize(context.Background(), req)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if action.RequestID == "" {
		t.Error("RequestID should be generated when header is absent")
	}

	// Verify it's a valid UUID
	if _, err := uuid.Parse(action.RequestID); err != nil {
		t.Errorf("RequestID %q is not a valid UUID: %v", action.RequestID, err)
	}
}

func TestHTTPNormalizer_Normalize_HeadersInArguments(t *testing.T) {
	normalizer := NewHTTPNormalizer()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("X-Custom-Header", "custom-value")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer secret-token")
	req.Header.Set("Proxy-Authorization", "Basic creds")

	action, err := normalizer.Normalize(context.Background(), req)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	headers, ok := action.Arguments["headers"].(map[string]interface{})
	if !ok {
		t.Fatal("Arguments[headers] should be a map[string]interface{}")
	}

	// Custom header should be present
	if headers["X-Custom-Header"] != "custom-value" {
		t.Errorf("headers[X-Custom-Header] = %v, want %q", headers["X-Custom-Header"], "custom-value")
	}
	if headers["Accept"] != "application/json" {
		t.Errorf("headers[Accept] = %v, want %q", headers["Accept"], "application/json")
	}

	// Sensitive headers should be excluded
	if _, exists := headers["Authorization"]; exists {
		t.Error("Authorization header should be excluded from Arguments")
	}
	if _, exists := headers["Proxy-Authorization"]; exists {
		t.Error("Proxy-Authorization header should be excluded from Arguments")
	}
}

func TestHTTPNormalizer_Denormalize_Allow(t *testing.T) {
	normalizer := NewHTTPNormalizer()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)

	ca := &CanonicalAction{
		OriginalMessage: req,
	}
	result := &InterceptResult{
		Decision: DecisionAllow,
	}

	resp, err := normalizer.Denormalize(ca, result)
	if err != nil {
		t.Fatalf("Denormalize() error = %v", err)
	}

	returnedReq, ok := resp.(*http.Request)
	if !ok {
		t.Fatalf("Denormalize() returned %T, want *http.Request", resp)
	}
	if returnedReq != req {
		t.Error("Denormalize() should return the exact original request")
	}
}

func TestHTTPNormalizer_Denormalize_Deny(t *testing.T) {
	normalizer := NewHTTPNormalizer()
	req := httptest.NewRequest(http.MethodGet, "http://malicious.com/", nil)

	ca := &CanonicalAction{
		OriginalMessage: req,
	}
	result := &InterceptResult{
		Decision: DecisionDeny,
		Reason:   "blocked by outbound policy",
		HelpText: "Contact admin for whitelist",
	}

	resp, err := normalizer.Denormalize(ca, result)
	if resp != nil {
		t.Errorf("Denormalize() returned non-nil response for deny: %v", resp)
	}
	if err == nil {
		t.Fatal("Denormalize() should return error for deny decision")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "blocked by outbound policy") {
		t.Errorf("Error message %q should contain reason", errMsg)
	}
	if !strings.Contains(errMsg, "Contact admin for whitelist") {
		t.Errorf("Error message %q should contain help text", errMsg)
	}
}

func TestHTTPNormalizer_Protocol(t *testing.T) {
	normalizer := NewHTTPNormalizer()
	if got := normalizer.Protocol(); got != "http" {
		t.Errorf("Protocol() = %q, want %q", got, "http")
	}
}

func TestHTTPNormalizer_Normalize_InvalidType(t *testing.T) {
	normalizer := NewHTTPNormalizer()

	_, err := normalizer.Normalize(context.Background(), "not an http request")
	if err == nil {
		t.Error("Normalize() should return error for non-*http.Request type")
	}
	if !strings.Contains(err.Error(), "expected *http.Request") {
		t.Errorf("Error message %q should mention expected type", err.Error())
	}
}

func TestHTTPNormalizer_Normalize_LargeBody(t *testing.T) {
	normalizer := NewHTTPNormalizer()

	// Create a body larger than 64KB
	largeBody := strings.Repeat("x", 70*1024)
	req := httptest.NewRequest(http.MethodPost, "http://example.com/upload", strings.NewReader(largeBody))
	req.Header.Set("Content-Type", "text/plain")

	action, err := normalizer.Normalize(context.Background(), req)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	// Body should be stored as string but truncated to 64KB
	bodyStr, ok := action.Arguments["body"].(string)
	if !ok {
		t.Fatal("Arguments[body] should be a string for text/plain content")
	}
	if len(bodyStr) > maxBodySize {
		t.Errorf("Body length = %d, should not exceed %d", len(bodyStr), maxBodySize)
	}
	if len(bodyStr) != maxBodySize {
		t.Errorf("Body length = %d, want %d (truncated)", len(bodyStr), maxBodySize)
	}
}

func TestHTTPNormalizer_Normalize_BodyPreserved(t *testing.T) {
	normalizer := NewHTTPNormalizer()
	originalBody := `{"key":"value"}`
	req := httptest.NewRequest(http.MethodPost, "http://example.com/api", strings.NewReader(originalBody))
	req.Header.Set("Content-Type", "application/json")

	_, err := normalizer.Normalize(context.Background(), req)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	// Body should be re-readable after normalization
	restoredBody, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("Re-reading body error = %v", err)
	}
	if string(restoredBody) != originalBody {
		t.Errorf("Restored body = %q, want %q", string(restoredBody), originalBody)
	}
}

func TestHTTPNormalizer_Normalize_EmptyBody(t *testing.T) {
	normalizer := NewHTTPNormalizer()
	req := httptest.NewRequest(http.MethodPost, "http://example.com/api", bytes.NewReader([]byte{}))
	req.Header.Set("Content-Type", "application/json")

	action, err := normalizer.Normalize(context.Background(), req)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	// Should not have a "body" key for empty body
	if _, exists := action.Arguments["body"]; exists {
		t.Error("Empty body should not produce a body key in Arguments")
	}
}

func TestHTTPNormalizer_Normalize_JSONWithCharset(t *testing.T) {
	normalizer := NewHTTPNormalizer()
	body := `{"status":"ok"}`
	req := httptest.NewRequest(http.MethodPost, "http://example.com/api", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")

	action, err := normalizer.Normalize(context.Background(), req)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	// Should still parse as JSON despite charset parameter
	if action.Arguments["status"] != "ok" {
		t.Errorf("Arguments[status] = %v, want %q", action.Arguments["status"], "ok")
	}
}

func TestHTTPNormalizer_Normalize_PUTRequest(t *testing.T) {
	normalizer := NewHTTPNormalizer()
	req := httptest.NewRequest(http.MethodPut, "http://example.com/resource/42", nil)

	action, err := normalizer.Normalize(context.Background(), req)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if action.Name != "PUT" {
		t.Errorf("Name = %q, want %q", action.Name, "PUT")
	}
	if action.Destination.Path != "/resource/42" {
		t.Errorf("Destination.Path = %q, want %q", action.Destination.Path, "/resource/42")
	}
}

func TestHTTPNormalizer_Normalize_DELETERequest(t *testing.T) {
	normalizer := NewHTTPNormalizer()
	req := httptest.NewRequest(http.MethodDelete, "http://example.com/resource/42", nil)

	action, err := normalizer.Normalize(context.Background(), req)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}

	if action.Name != "DELETE" {
		t.Errorf("Name = %q, want %q", action.Name, "DELETE")
	}
}
