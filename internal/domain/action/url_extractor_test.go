package action

import (
	"testing"
)

func TestExtractURLs_NilInput(t *testing.T) {
	results := ExtractURLs(nil, ExtractOptions{})
	if results == nil {
		t.Fatal("expected non-nil empty slice, got nil")
	}
	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
}

func TestExtractURLs_EmptyMap(t *testing.T) {
	results := ExtractURLs(map[string]interface{}{}, ExtractOptions{})
	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
}

func TestExtractURLs_SimpleHTTPS(t *testing.T) {
	args := map[string]interface{}{
		"url": "https://api.example.com/v1",
	}
	results := ExtractURLs(args, ExtractOptions{})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.URL != "https://api.example.com/v1" {
		t.Errorf("URL = %q, want %q", r.URL, "https://api.example.com/v1")
	}
	if r.Domain != "api.example.com" {
		t.Errorf("Domain = %q, want %q", r.Domain, "api.example.com")
	}
	if r.Port != 443 {
		t.Errorf("Port = %d, want 443", r.Port)
	}
	if r.Scheme != "https" {
		t.Errorf("Scheme = %q, want %q", r.Scheme, "https")
	}
	if r.Path != "/v1" {
		t.Errorf("Path = %q, want %q", r.Path, "/v1")
	}
	if r.Source != "url" {
		t.Errorf("Source = %q, want %q", r.Source, "url")
	}
	if r.IP != "" {
		t.Errorf("IP = %q, want empty", r.IP)
	}
}

func TestExtractURLs_SimpleHTTP(t *testing.T) {
	args := map[string]interface{}{
		"endpoint": "http://localhost:8080/api",
	}
	results := ExtractURLs(args, ExtractOptions{})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.URL != "http://localhost:8080/api" {
		t.Errorf("URL = %q, want %q", r.URL, "http://localhost:8080/api")
	}
	if r.Domain != "localhost" {
		t.Errorf("Domain = %q, want %q", r.Domain, "localhost")
	}
	if r.Port != 8080 {
		t.Errorf("Port = %d, want 8080", r.Port)
	}
	if r.Scheme != "http" {
		t.Errorf("Scheme = %q, want %q", r.Scheme, "http")
	}
	if r.Path != "/api" {
		t.Errorf("Path = %q, want %q", r.Path, "/api")
	}
}

func TestExtractURLs_IPPort(t *testing.T) {
	args := map[string]interface{}{
		"host": "192.168.1.1:8080",
	}
	results := ExtractURLs(args, ExtractOptions{})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.IP != "192.168.1.1" {
		t.Errorf("IP = %q, want %q", r.IP, "192.168.1.1")
	}
	if r.Port != 8080 {
		t.Errorf("Port = %d, want 8080", r.Port)
	}
	if r.URL != "http://192.168.1.1:8080" {
		t.Errorf("URL = %q, want %q", r.URL, "http://192.168.1.1:8080")
	}
	if r.Source != "host" {
		t.Errorf("Source = %q, want %q", r.Source, "host")
	}
	if r.Domain != "" {
		t.Errorf("Domain = %q, want empty", r.Domain)
	}
}

func TestExtractURLs_IPOnly(t *testing.T) {
	args := map[string]interface{}{
		"target": "10.0.0.1",
	}
	results := ExtractURLs(args, ExtractOptions{})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.IP != "10.0.0.1" {
		t.Errorf("IP = %q, want %q", r.IP, "10.0.0.1")
	}
	if r.Port != 0 {
		t.Errorf("Port = %d, want 0", r.Port)
	}
	if r.URL != "http://10.0.0.1" {
		t.Errorf("URL = %q, want %q", r.URL, "http://10.0.0.1")
	}
}

func TestExtractURLs_InvalidIPOctets(t *testing.T) {
	args := map[string]interface{}{
		"host": "999.999.999.999:8080",
	}
	results := ExtractURLs(args, ExtractOptions{})
	if len(results) != 0 {
		t.Fatalf("expected 0 results for invalid IP octets, got %d", len(results))
	}
}

func TestExtractURLs_NestedMap(t *testing.T) {
	args := map[string]interface{}{
		"config": map[string]interface{}{
			"nested": map[string]interface{}{
				"endpoint": "http://internal:3000/api",
			},
		},
	}
	results := ExtractURLs(args, ExtractOptions{})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.URL != "http://internal:3000/api" {
		t.Errorf("URL = %q, want %q", r.URL, "http://internal:3000/api")
	}
	if r.Domain != "internal" {
		t.Errorf("Domain = %q, want %q", r.Domain, "internal")
	}
	if r.Port != 3000 {
		t.Errorf("Port = %d, want 3000", r.Port)
	}
	if r.Source != "config.nested.endpoint" {
		t.Errorf("Source = %q, want %q", r.Source, "config.nested.endpoint")
	}
}

func TestExtractURLs_Slice(t *testing.T) {
	args := map[string]interface{}{
		"items": []interface{}{"https://a.com", "https://b.com"},
	}
	results := ExtractURLs(args, ExtractOptions{})
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	urls := map[string]bool{}
	for _, r := range results {
		urls[r.URL] = true
	}
	if !urls["https://a.com"] {
		t.Error("missing https://a.com")
	}
	if !urls["https://b.com"] {
		t.Error("missing https://b.com")
	}
}

func TestExtractURLs_EmbeddedInText(t *testing.T) {
	args := map[string]interface{}{
		"text": "Connect to https://foo.com and also http://bar.com/path for more",
	}
	results := ExtractURLs(args, ExtractOptions{})
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	urls := map[string]bool{}
	for _, r := range results {
		urls[r.URL] = true
	}
	if !urls["https://foo.com"] {
		t.Error("missing https://foo.com")
	}
	if !urls["http://bar.com/path"] {
		t.Error("missing http://bar.com/path")
	}
}

func TestExtractURLs_NumbersNotExtracted(t *testing.T) {
	args := map[string]interface{}{
		"port":  8080,
		"count": 42,
	}
	results := ExtractURLs(args, ExtractOptions{})
	if len(results) != 0 {
		t.Fatalf("expected 0 results for numeric values, got %d", len(results))
	}
}

func TestExtractURLs_BoolNotExtracted(t *testing.T) {
	args := map[string]interface{}{
		"enabled": true,
	}
	results := ExtractURLs(args, ExtractOptions{})
	if len(results) != 0 {
		t.Fatalf("expected 0 results for bool values, got %d", len(results))
	}
}

func TestExtractURLs_Base64Decode(t *testing.T) {
	// "https://evil.com" base64 encoded
	args := map[string]interface{}{
		"data": "aHR0cHM6Ly9ldmlsLmNvbQ==",
	}

	// Without base64 decoding
	results := ExtractURLs(args, ExtractOptions{Base64Decode: false})
	for _, r := range results {
		if r.URL == "https://evil.com" {
			t.Error("should not decode base64 when Base64Decode is false")
		}
	}

	// With base64 decoding
	results = ExtractURLs(args, ExtractOptions{Base64Decode: true})
	found := false
	for _, r := range results {
		if r.URL == "https://evil.com" {
			found = true
			if r.Domain != "evil.com" {
				t.Errorf("Domain = %q, want %q", r.Domain, "evil.com")
			}
			if r.Port != 443 {
				t.Errorf("Port = %d, want 443", r.Port)
			}
			if r.Source != "data" {
				t.Errorf("Source = %q, want %q", r.Source, "data")
			}
			break
		}
	}
	if !found {
		t.Error("expected to find https://evil.com when Base64Decode is true")
	}
}

func TestExtractURLs_Base64NonURL(t *testing.T) {
	// Base64 of "hello world" - not a URL
	args := map[string]interface{}{
		"data": "aGVsbG8gd29ybGQ=",
	}
	results := ExtractURLs(args, ExtractOptions{Base64Decode: true})
	if len(results) != 0 {
		t.Fatalf("expected 0 results for non-URL base64, got %d", len(results))
	}
}

func TestExtractURLs_MaxDepth(t *testing.T) {
	// Build a deeply nested structure beyond MaxDepth
	args := map[string]interface{}{
		"level1": map[string]interface{}{
			"level2": map[string]interface{}{
				"level3": map[string]interface{}{
					"url": "https://deep.example.com",
				},
			},
		},
	}

	// MaxDepth = 2 should not reach level 3
	results := ExtractURLs(args, ExtractOptions{MaxDepth: 2})
	if len(results) != 0 {
		t.Fatalf("expected 0 results with MaxDepth=2, got %d", len(results))
	}

	// MaxDepth = 4 should reach it
	results = ExtractURLs(args, ExtractOptions{MaxDepth: 4})
	if len(results) != 1 {
		t.Fatalf("expected 1 result with MaxDepth=4, got %d", len(results))
	}
}

func TestExtractURLs_DefaultMaxDepth(t *testing.T) {
	// MaxDepth = 0 should default to 10
	args := map[string]interface{}{
		"url": "https://example.com",
	}
	results := ExtractURLs(args, ExtractOptions{MaxDepth: 0})
	if len(results) != 1 {
		t.Fatalf("expected 1 result with default MaxDepth, got %d", len(results))
	}
}

func TestExtractURLs_Deduplication(t *testing.T) {
	args := map[string]interface{}{
		"url1": "https://example.com",
		"url2": "https://example.com",
	}
	results := ExtractURLs(args, ExtractOptions{})
	if len(results) != 1 {
		t.Fatalf("expected 1 result (deduplicated), got %d", len(results))
	}
}

func TestExtractURLs_WSScheme(t *testing.T) {
	args := map[string]interface{}{
		"ws": "ws://realtime.example.com/events",
	}
	results := ExtractURLs(args, ExtractOptions{})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.Scheme != "ws" {
		t.Errorf("Scheme = %q, want %q", r.Scheme, "ws")
	}
	if r.Port != 80 {
		t.Errorf("Port = %d, want 80", r.Port)
	}
}

func TestExtractURLs_WSSScheme(t *testing.T) {
	args := map[string]interface{}{
		"ws": "wss://secure.example.com/events",
	}
	results := ExtractURLs(args, ExtractOptions{})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.Scheme != "wss" {
		t.Errorf("Scheme = %q, want %q", r.Scheme, "wss")
	}
	if r.Port != 443 {
		t.Errorf("Port = %d, want 443", r.Port)
	}
}

func TestExtractURLs_TrailingPunctuation(t *testing.T) {
	args := map[string]interface{}{
		"text": "Visit https://example.com/page. Then go to http://other.com,",
	}
	results := ExtractURLs(args, ExtractOptions{})
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	urls := map[string]bool{}
	for _, r := range results {
		urls[r.URL] = true
	}
	if !urls["https://example.com/page"] {
		t.Errorf("expected https://example.com/page, got urls: %v", urls)
	}
	if !urls["http://other.com"] {
		t.Errorf("expected http://other.com, got urls: %v", urls)
	}
}

func TestExtractURLs_MixedContent(t *testing.T) {
	args := map[string]interface{}{
		"url":   "https://api.example.com",
		"host":  "10.0.0.5:9090",
		"count": 100,
		"nested": map[string]interface{}{
			"endpoint": "http://internal:3000",
		},
	}
	results := ExtractURLs(args, ExtractOptions{})
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
}

func TestExtractURLs_SliceSourcePath(t *testing.T) {
	args := map[string]interface{}{
		"servers": []interface{}{"https://a.com", "https://b.com"},
	}
	results := ExtractURLs(args, ExtractOptions{})
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	// Verify source paths include index
	sources := map[string]bool{}
	for _, r := range results {
		sources[r.Source] = true
	}
	if !sources["servers[0]"] {
		t.Errorf("expected source servers[0], got %v", sources)
	}
	if !sources["servers[1]"] {
		t.Errorf("expected source servers[1], got %v", sources)
	}
}

func TestExtractURLs_InvalidPort(t *testing.T) {
	args := map[string]interface{}{
		"host": "192.168.1.1:99999",
	}
	results := ExtractURLs(args, ExtractOptions{})
	if len(results) != 0 {
		t.Fatalf("expected 0 results for invalid port, got %d", len(results))
	}
}

func TestExtractURLs_DefaultPort_HTTP(t *testing.T) {
	args := map[string]interface{}{
		"url": "http://example.com",
	}
	results := ExtractURLs(args, ExtractOptions{})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Port != 80 {
		t.Errorf("Port = %d, want 80", results[0].Port)
	}
}

func TestExtractURLs_URLWithQueryString(t *testing.T) {
	args := map[string]interface{}{
		"url": "https://api.example.com/search?q=test&page=1",
	}
	results := ExtractURLs(args, ExtractOptions{})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.Domain != "api.example.com" {
		t.Errorf("Domain = %q, want %q", r.Domain, "api.example.com")
	}
	if r.Path != "/search" {
		t.Errorf("Path = %q, want %q", r.Path, "/search")
	}
}

func TestExtractURLs_PlainStringNotURL(t *testing.T) {
	args := map[string]interface{}{
		"name":  "hello world",
		"value": "just a string",
	}
	results := ExtractURLs(args, ExtractOptions{})
	if len(results) != 0 {
		t.Fatalf("expected 0 results for plain strings, got %d", len(results))
	}
}

func TestExtractURLs_IPInText(t *testing.T) {
	args := map[string]interface{}{
		"msg": "connect to 192.168.0.1:443 for secure access",
	}
	results := ExtractURLs(args, ExtractOptions{})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.IP != "192.168.0.1" {
		t.Errorf("IP = %q, want %q", r.IP, "192.168.0.1")
	}
	if r.Port != 443 {
		t.Errorf("Port = %d, want 443", r.Port)
	}
}
