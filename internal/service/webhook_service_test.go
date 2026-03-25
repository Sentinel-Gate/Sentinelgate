package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/event"
)

// newTestWebhookService creates a webhook service with a plain HTTP client
// (no SSRF dialer) suitable for testing against httptest.Server on localhost.
func newTestWebhookService(url, secret string, events []string) *WebhookService {
	svc := NewWebhookService(url, secret, events, slog.Default())
	svc.SetHTTPClient(&http.Client{Timeout: 10 * time.Second})
	return svc
}

func TestWebhookService_Send(t *testing.T) {
	var received WebhookPayload
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &received)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	svc := newTestWebhookService(server.URL, "", nil)
	svc.send(event.Event{
		Type:     "test.event",
		Source:   "test",
		Severity: event.SeverityWarning,
		Payload:  map[string]string{"key": "value"},
	})

	// Give it a moment
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if received.Type != "test.event" {
		t.Errorf("expected type test.event, got %s", received.Type)
	}
	if received.Severity != "warning" {
		t.Errorf("expected severity warning, got %s", received.Severity)
	}
}

func TestWebhookService_HMAC(t *testing.T) {
	secret := "test-secret-key"
	var receivedSig string
	var receivedBody []byte
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		receivedSig = r.Header.Get("X-Signature-256")
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	svc := newTestWebhookService(server.URL, secret, nil)
	svc.send(event.Event{
		Type:   "test.hmac",
		Source: "test",
	})

	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if receivedSig == "" {
		t.Fatal("expected X-Signature-256 header")
	}

	// Verify HMAC
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(receivedBody)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if receivedSig != expected {
		t.Errorf("HMAC mismatch: got %s, expected %s", receivedSig, expected)
	}
}

func TestWebhookService_EventFilter(t *testing.T) {
	callCount := 0
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		callCount++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Only receive approval.hold events
	svc := newTestWebhookService(server.URL, "", []string{"approval.hold"})

	// This should be sent
	svc.send(event.Event{Type: "approval.hold", Source: "test"})
	// This should be filtered out — but send() doesn't check filter, SubscribeToBus does
	// So we test via the bus integration

	bus := event.NewBus(100)
	bus.Start()
	defer bus.Stop()

	svc2 := newTestWebhookService(server.URL, "", []string{"approval.hold"})
	svc2.SubscribeToBus(bus)
	defer svc2.Stop()

	// Filtered: should NOT be sent
	bus.Publish(context.TODO(), event.Event{Type: "drift.anomaly", Source: "test"})
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	beforeCount := callCount
	mu.Unlock()

	// Matching: should be sent
	bus.Publish(context.TODO(), event.Event{Type: "approval.hold", Source: "test"})
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	afterCount := callCount
	mu.Unlock()

	if afterCount <= beforeCount {
		t.Error("expected webhook to be called for matching event")
	}
}

func TestWebhookService_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	// Should not panic on server error
	svc := newTestWebhookService(server.URL, "", nil)
	svc.send(event.Event{Type: "test", Source: "test"})
}

func TestWebhookService_InvalidURL(t *testing.T) {
	// Should not panic on invalid URL
	svc := newTestWebhookService("http://localhost:99999/nonexistent", "", nil)
	svc.send(event.Event{Type: "test", Source: "test"})
}

func TestWebhookService_ContentType(t *testing.T) {
	var contentType string
	var mu sync.Mutex

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		contentType = r.Header.Get("Content-Type")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	svc := newTestWebhookService(server.URL, "", nil)
	svc.send(event.Event{Type: "test", Source: "test"})

	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if contentType != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", contentType)
	}
}
