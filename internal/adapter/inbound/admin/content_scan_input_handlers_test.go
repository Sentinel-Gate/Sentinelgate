package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/state"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/action"
	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/event"
)

func newTestHandlerWithContentScan(t *testing.T) (*AdminAPIHandler, string) {
	t.Helper()
	tmpDir := t.TempDir()
	statePath := tmpDir + "/state.json"

	store := state.NewFileStateStore(statePath, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	scanner := action.NewContentScanner()
	interceptor := action.NewContentScanInterceptor(scanner, nil, true, slog.New(slog.NewTextHandler(os.Stderr, nil)))

	handler := NewAdminAPIHandler(
		WithStateStore(store),
		WithAPILogger(slog.New(slog.NewTextHandler(os.Stderr, nil))),
	)
	handler.contentScanInterceptor = interceptor

	return handler, statePath
}

func TestHandleGetInputScanning(t *testing.T) {
	h, _ := newTestHandlerWithContentScan(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/security/input-scanning", nil)
	w := httptest.NewRecorder()

	h.handleGetInputScanning(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var resp inputScanConfigResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Enabled {
		t.Error("expected enabled=true")
	}
}

func TestHandleUpdateInputScanning(t *testing.T) {
	h, _ := newTestHandlerWithContentScan(t)

	body := `{"enabled": false}`
	req := httptest.NewRequest(http.MethodPut, "/admin/api/v1/security/input-scanning", bytes.NewBufferString(body))
	w := httptest.NewRecorder()

	h.handleUpdateInputScanning(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if h.contentScanInterceptor.Enabled() {
		t.Error("expected scanning to be disabled after update")
	}
}

func TestHandleAddWhitelist(t *testing.T) {
	h, _ := newTestHandlerWithContentScan(t)

	body := `{"pattern_type": "email", "scope": "tool", "value": "read_file"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api/v1/security/input-scanning/whitelist", bytes.NewBufferString(body))
	w := httptest.NewRecorder()

	h.handleAddWhitelist(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	entries := h.contentScanInterceptor.GetWhitelist()
	if len(entries) != 1 {
		t.Fatalf("expected 1 whitelist entry, got %d", len(entries))
	}
	if entries[0].Value != "read_file" {
		t.Errorf("expected value read_file, got %s", entries[0].Value)
	}
}

func TestHandleAddWhitelist_InvalidScope(t *testing.T) {
	h, _ := newTestHandlerWithContentScan(t)

	body := `{"pattern_type": "email", "scope": "invalid", "value": "test"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api/v1/security/input-scanning/whitelist", bytes.NewBufferString(body))
	w := httptest.NewRecorder()

	h.handleAddWhitelist(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleAddWhitelist_MissingFields(t *testing.T) {
	h, _ := newTestHandlerWithContentScan(t)

	body := `{"pattern_type": "email"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api/v1/security/input-scanning/whitelist", bytes.NewBufferString(body))
	w := httptest.NewRecorder()

	h.handleAddWhitelist(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleRemoveWhitelist(t *testing.T) {
	h, _ := newTestHandlerWithContentScan(t)

	// First add an entry.
	h.contentScanInterceptor.AddWhitelistEntry(action.WhitelistEntry{
		ID:          "wl_test",
		PatternType: action.PatternEmail,
		Scope:       action.WhitelistScopeTool,
		Value:       "read_file",
	})

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/v1/security/input-scanning/whitelist/wl_test", nil)
	req.SetPathValue("id", "wl_test")
	w := httptest.NewRecorder()

	h.handleRemoveWhitelist(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if len(h.contentScanInterceptor.GetWhitelist()) != 0 {
		t.Error("expected 0 entries after removal")
	}
}

func TestHandleRemoveWhitelist_NotFound(t *testing.T) {
	h, _ := newTestHandlerWithContentScan(t)

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/v1/security/input-scanning/whitelist/nonexistent", nil)
	req.SetPathValue("id", "nonexistent")
	w := httptest.NewRecorder()

	h.handleRemoveWhitelist(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestHandleGetInputScanning_NoInterceptor(t *testing.T) {
	handler := NewAdminAPIHandler(
		WithAPILogger(slog.New(slog.NewTextHandler(os.Stderr, nil))),
	)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/security/input-scanning", nil)
	w := httptest.NewRecorder()

	handler.handleGetInputScanning(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
}

func TestHandleAddWhitelist_EmitsEvent(t *testing.T) {
	h, _ := newTestHandlerWithContentScan(t)

	bus := event.NewBus(100)
	bus.Start()
	defer bus.Stop()
	h.eventBus = bus

	var mu sync.Mutex
	var received []event.Event
	bus.Subscribe("content.whitelist_added", func(_ context.Context, evt event.Event) {
		mu.Lock()
		received = append(received, evt)
		mu.Unlock()
	})

	body := `{"pattern_type": "email", "scope": "tool", "value": "read_file"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api/v1/security/input-scanning/whitelist", bytes.NewBufferString(body))
	w := httptest.NewRecorder()

	h.handleAddWhitelist(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	// Wait for async event delivery.
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Fatalf("expected 1 event, got %d", len(received))
	}
	evt := received[0]
	if evt.Type != "content.whitelist_added" {
		t.Errorf("type = %q, want content.whitelist_added", evt.Type)
	}
	if evt.Source != "content-scanning" {
		t.Errorf("source = %q, want content-scanning", evt.Source)
	}
	p, ok := evt.Payload.(map[string]string)
	if !ok {
		t.Fatalf("payload is not map[string]string: %T", evt.Payload)
	}
	if p["pattern_type"] != "email" {
		t.Errorf("pattern_type = %q, want email", p["pattern_type"])
	}
	if p["scope"] != "tool" {
		t.Errorf("scope = %q, want tool", p["scope"])
	}
	if p["value"] != "read_file" {
		t.Errorf("value = %q, want read_file", p["value"])
	}
}

func TestHandleRemoveWhitelist_EmitsEvent(t *testing.T) {
	h, _ := newTestHandlerWithContentScan(t)

	bus := event.NewBus(100)
	bus.Start()
	defer bus.Stop()
	h.eventBus = bus

	// Add an entry to remove.
	h.contentScanInterceptor.AddWhitelistEntry(action.WhitelistEntry{
		ID:          "wl_test",
		PatternType: action.PatternEmail,
		Scope:       action.WhitelistScopeTool,
		Value:       "read_file",
	})

	var mu sync.Mutex
	var received []event.Event
	bus.Subscribe("content.whitelist_removed", func(_ context.Context, evt event.Event) {
		mu.Lock()
		received = append(received, evt)
		mu.Unlock()
	})

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/v1/security/input-scanning/whitelist/wl_test", nil)
	req.SetPathValue("id", "wl_test")
	w := httptest.NewRecorder()

	h.handleRemoveWhitelist(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Wait for async event delivery.
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Fatalf("expected 1 event, got %d", len(received))
	}
	evt := received[0]
	if evt.Type != "content.whitelist_removed" {
		t.Errorf("type = %q, want content.whitelist_removed", evt.Type)
	}
	if evt.Source != "content-scanning" {
		t.Errorf("source = %q, want content-scanning", evt.Source)
	}
	p, ok := evt.Payload.(map[string]string)
	if !ok {
		t.Fatalf("payload is not map[string]string: %T", evt.Payload)
	}
	if p["pattern_type"] != "email" {
		t.Errorf("pattern_type = %q, want email", p["pattern_type"])
	}
	if p["scope"] != "tool" {
		t.Errorf("scope = %q, want tool", p["scope"])
	}
	if p["value"] != "read_file" {
		t.Errorf("value = %q, want read_file", p["value"])
	}
}

func TestHandleAddWhitelist_NoEventBus(t *testing.T) {
	h, _ := newTestHandlerWithContentScan(t)
	// eventBus is nil -- should not panic.

	body := `{"pattern_type": "email", "scope": "tool", "value": "test"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/api/v1/security/input-scanning/whitelist", bytes.NewBufferString(body))
	w := httptest.NewRecorder()

	h.handleAddWhitelist(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleRemoveWhitelist_NoEventBus(t *testing.T) {
	h, _ := newTestHandlerWithContentScan(t)
	// eventBus is nil -- should not panic.

	h.contentScanInterceptor.AddWhitelistEntry(action.WhitelistEntry{
		ID:          "wl_noevent",
		PatternType: action.PatternEmail,
		Scope:       action.WhitelistScopeTool,
		Value:       "test",
	})

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/v1/security/input-scanning/whitelist/wl_noevent", nil)
	req.SetPathValue("id", "wl_noevent")
	w := httptest.NewRecorder()

	h.handleRemoveWhitelist(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}
