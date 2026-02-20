package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/inbound/httpgw"
)

// mockHTTPGatewayController implements HTTPGatewayController for testing.
type mockHTTPGatewayController struct {
	tlsEnabled bool
	bypassList []string
	targets    []httpgw.UpstreamTarget
	caCertPEM  []byte
}

func (m *mockHTTPGatewayController) TLSEnabled() bool                           { return m.tlsEnabled }
func (m *mockHTTPGatewayController) SetTLSEnabled(enabled bool)                 { m.tlsEnabled = enabled }
func (m *mockHTTPGatewayController) BypassList() []string                       { return m.bypassList }
func (m *mockHTTPGatewayController) SetBypassList(list []string)                { m.bypassList = list }
func (m *mockHTTPGatewayController) Targets() []httpgw.UpstreamTarget           { return m.targets }
func (m *mockHTTPGatewayController) SetTargets(targets []httpgw.UpstreamTarget) { m.targets = targets }
func (m *mockHTTPGatewayController) CACertPEM() []byte                          { return m.caCertPEM }

func newTestAPIHandlerWithGateway(ctrl HTTPGatewayController) *AdminAPIHandler {
	h := NewAdminAPIHandler()
	h.httpGatewayCtrl = ctrl
	return h
}

func TestHTTPGatewayConfig(t *testing.T) {
	ctrl := &mockHTTPGatewayController{
		tlsEnabled: true,
		bypassList: []string{"*.google.com", "example.com"},
		targets: []httpgw.UpstreamTarget{
			{
				ID:          "target-1",
				Name:        "OpenAI",
				PathPrefix:  "/api/openai/",
				Upstream:    "https://api.openai.com",
				StripPrefix: true,
				Enabled:     true,
			},
		},
	}

	h := newTestAPIHandlerWithGateway(ctrl)

	req := httptest.NewRequest("GET", "/admin/api/v1/security/http-gateway", nil)
	rec := httptest.NewRecorder()

	h.handleGetHTTPGatewayConfig(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp httpGatewayConfigResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !resp.TLSInspection.Enabled {
		t.Error("expected TLS inspection enabled")
	}
	if len(resp.TLSInspection.BypassList) != 2 {
		t.Errorf("expected 2 bypass domains, got %d", len(resp.TLSInspection.BypassList))
	}
	if len(resp.Targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(resp.Targets))
	}
	if resp.Targets[0].Name != "OpenAI" {
		t.Errorf("expected target name 'OpenAI', got %q", resp.Targets[0].Name)
	}
	if !resp.SinglePort {
		t.Error("expected single_port true")
	}
}

func TestHTTPGatewayConfig_503(t *testing.T) {
	h := NewAdminAPIHandler() // no controller set

	req := httptest.NewRequest("GET", "/admin/api/v1/security/http-gateway", nil)
	rec := httptest.NewRecorder()

	h.handleGetHTTPGatewayConfig(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
}

func TestHTTPGatewayPutTLSConfig(t *testing.T) {
	ctrl := &mockHTTPGatewayController{
		tlsEnabled: false,
		bypassList: nil,
	}

	h := newTestAPIHandlerWithGateway(ctrl)

	body, _ := json.Marshal(map[string]interface{}{
		"enabled":     true,
		"bypass_list": []string{"*.google.com", "*.github.com"},
	})

	req := httptest.NewRequest("PUT", "/admin/api/v1/security/http-gateway/tls", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.handlePutHTTPGatewayTLS(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	if !ctrl.tlsEnabled {
		t.Error("expected TLS to be enabled")
	}
	if len(ctrl.bypassList) != 2 {
		t.Errorf("expected 2 bypass entries, got %d", len(ctrl.bypassList))
	}
}

func TestHTTPGatewayPutTLSConfig_InvalidBypass(t *testing.T) {
	ctrl := &mockHTTPGatewayController{}
	h := newTestAPIHandlerWithGateway(ctrl)

	body, _ := json.Marshal(map[string]interface{}{
		"enabled":     true,
		"bypass_list": []string{"valid.com", "  "},
	})

	req := httptest.NewRequest("PUT", "/admin/api/v1/security/http-gateway/tls", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.handlePutHTTPGatewayTLS(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTPGatewayGetCACert(t *testing.T) {
	ctrl := &mockHTTPGatewayController{
		caCertPEM: []byte("-----BEGIN CERTIFICATE-----\nMIIBfake...\n-----END CERTIFICATE-----\n"),
	}

	h := newTestAPIHandlerWithGateway(ctrl)

	req := httptest.NewRequest("GET", "/admin/api/v1/security/http-gateway/ca-cert", nil)
	rec := httptest.NewRecorder()

	h.handleGetCACert(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "application/x-pem-file" {
		t.Errorf("expected Content-Type 'application/x-pem-file', got %q", ct)
	}

	cd := rec.Header().Get("Content-Disposition")
	if cd != `attachment; filename="sentinelgate-ca.pem"` {
		t.Errorf("unexpected Content-Disposition: %q", cd)
	}

	if !bytes.Contains(rec.Body.Bytes(), []byte("BEGIN CERTIFICATE")) {
		t.Error("expected PEM certificate in body")
	}
}

func TestHTTPGatewayGetCACert_404(t *testing.T) {
	ctrl := &mockHTTPGatewayController{
		caCertPEM: nil,
	}

	h := newTestAPIHandlerWithGateway(ctrl)

	req := httptest.NewRequest("GET", "/admin/api/v1/security/http-gateway/ca-cert", nil)
	rec := httptest.NewRecorder()

	h.handleGetCACert(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHTTPGatewayGetSetupScript(t *testing.T) {
	ctrl := &mockHTTPGatewayController{}
	h := newTestAPIHandlerWithGateway(ctrl)

	req := httptest.NewRequest("GET", "/admin/api/v1/security/http-gateway/setup-script", nil)
	req.Host = "localhost:3000"
	rec := httptest.NewRecorder()

	h.handleGetSetupScript(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	ct := rec.Header().Get("Content-Type")
	if ct != "text/x-shellscript" {
		t.Errorf("expected Content-Type 'text/x-shellscript', got %q", ct)
	}

	body := rec.Body.String()
	if !bytes.Contains([]byte(body), []byte("#!/bin/bash")) {
		t.Error("expected shell script header")
	}
	if !bytes.Contains([]byte(body), []byte("localhost:3000")) {
		t.Error("expected server address in script")
	}
}

func TestHTTPGatewayCreateTarget(t *testing.T) {
	ctrl := &mockHTTPGatewayController{
		targets: []httpgw.UpstreamTarget{},
	}
	h := newTestAPIHandlerWithGateway(ctrl)

	body, _ := json.Marshal(map[string]interface{}{
		"name":         "Test API",
		"path_prefix":  "/api/test/",
		"upstream":     "https://api.test.com",
		"strip_prefix": true,
	})

	req := httptest.NewRequest("POST", "/admin/api/v1/security/http-gateway/targets", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	h.handleCreateTarget(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp httpGatewayTargetJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Name != "Test API" {
		t.Errorf("expected name 'Test API', got %q", resp.Name)
	}
	if resp.ID == "" {
		t.Error("expected non-empty ID")
	}
	if !resp.Enabled {
		t.Error("expected target enabled by default")
	}

	// Check controller was updated
	if len(ctrl.targets) != 1 {
		t.Fatalf("expected 1 target in controller, got %d", len(ctrl.targets))
	}
}

func TestHTTPGatewayCreateTarget_Validation(t *testing.T) {
	ctrl := &mockHTTPGatewayController{}
	h := newTestAPIHandlerWithGateway(ctrl)

	tests := []struct {
		name   string
		body   map[string]interface{}
		expect int
	}{
		{"empty name", map[string]interface{}{"name": "", "path_prefix": "/api/", "upstream": "https://test.com"}, 400},
		{"no slash prefix", map[string]interface{}{"name": "test", "path_prefix": "api/", "upstream": "https://test.com"}, 400},
		{"invalid upstream", map[string]interface{}{"name": "test", "path_prefix": "/api/", "upstream": "not-a-url"}, 400},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.body)
			req := httptest.NewRequest("POST", "/admin/api/v1/security/http-gateway/targets", bytes.NewReader(body))
			rec := httptest.NewRecorder()
			h.handleCreateTarget(rec, req)
			if rec.Code != tt.expect {
				t.Errorf("expected %d, got %d: %s", tt.expect, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestHTTPGatewayDeleteTarget(t *testing.T) {
	ctrl := &mockHTTPGatewayController{
		targets: []httpgw.UpstreamTarget{
			{ID: "target-1", Name: "Test", PathPrefix: "/api/", Upstream: "https://api.test.com", Enabled: true},
			{ID: "target-2", Name: "Other", PathPrefix: "/other/", Upstream: "https://other.test.com", Enabled: true},
		},
	}
	h := newTestAPIHandlerWithGateway(ctrl)

	req := httptest.NewRequest("DELETE", "/admin/api/v1/security/http-gateway/targets/target-1", nil)
	req.SetPathValue("id", "target-1")
	rec := httptest.NewRecorder()

	h.handleDeleteTarget(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// Check controller was updated: should have 1 target left
	if len(ctrl.targets) != 1 {
		t.Fatalf("expected 1 target remaining, got %d", len(ctrl.targets))
	}
	if ctrl.targets[0].ID != "target-2" {
		t.Errorf("expected remaining target 'target-2', got %q", ctrl.targets[0].ID)
	}
}
