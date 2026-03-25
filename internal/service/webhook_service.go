package service

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"syscall"
	"time"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/event"
)

// WebhookService sends event notifications to a configured HTTP endpoint.
// It subscribes to the Event Bus and POSTs JSON payloads for matching events.
type WebhookService struct {
	url        string
	secret     string
	events     map[string]bool // empty = all events
	client     *http.Client
	logger     *slog.Logger
	mu          sync.Mutex
	unsubscribe func()
	wg          sync.WaitGroup    // H-4/M-29: tracks in-flight sends
	sendSem     chan struct{}      // H-4: bounded concurrency semaphore
	stopCh      chan struct{}      // H-9: signals goroutines to abort semaphore wait
}

// WebhookPayload is the JSON body sent to the webhook endpoint.
type WebhookPayload struct {
	Type           string    `json:"type"`
	Source         string    `json:"source"`
	Severity       string    `json:"severity"`
	Timestamp      time.Time `json:"timestamp"`
	RequiresAction bool      `json:"requires_action"`
	Payload        any       `json:"payload,omitempty"`
}

// NewWebhookService creates a webhook notification service.
// H-1: Uses SSRF-safe dialer to prevent DNS rebinding attacks at TCP connect time.
func NewWebhookService(url, secret string, eventFilter []string, logger *slog.Logger) *WebhookService {
	events := make(map[string]bool)
	for _, e := range eventFilter {
		events[e] = true
	}
	return &WebhookService{
		url:    url,
		secret: secret,
		events: events,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				DialContext: webhookSSRFSafeDialer().DialContext,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		logger:  logger,
		sendSem: make(chan struct{}, 10), // H-4: max 10 concurrent sends
		stopCh:  make(chan struct{}),     // H-9: stop channel for graceful shutdown
	}
}

// SetHTTPClient overrides the default SSRF-safe HTTP client (for testing only).
func (s *WebhookService) SetHTTPClient(c *http.Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.client = c
}

// webhookSSRFSafeDialer returns a net.Dialer that rejects connections to
// private/loopback/link-local IPs at TCP connect time to prevent SSRF.
func webhookSSRFSafeDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("SSRF protection: invalid address %q", address)
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return nil
			}
			if ip.IsLoopback() {
				return fmt.Errorf("SSRF protection: loopback IP %s blocked", ip)
			}
			if ip.IsPrivate() {
				return fmt.Errorf("SSRF protection: private IP %s blocked", ip)
			}
			if ip.IsUnspecified() {
				return fmt.Errorf("SSRF protection: unspecified IP %s blocked", ip)
			}
			if ip.IsLinkLocalUnicast() {
				return fmt.Errorf("SSRF protection: link-local IP %s blocked (cloud metadata)", ip)
			}
			if ip.IsLinkLocalMulticast() {
				return fmt.Errorf("SSRF protection: link-local multicast IP %s blocked", ip)
			}
			return nil
		},
	}
}

// SubscribeToBus registers the webhook as a consumer of events on the bus.
// H-4: send() is dispatched asynchronously with bounded concurrency to avoid
// blocking the event bus dispatch loop.
func (s *WebhookService) SubscribeToBus(bus event.Bus) {
	unsub := bus.SubscribeAll(func(ctx context.Context, evt event.Event) {
		if len(s.events) > 0 && !s.events[evt.Type] {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			// H-9: Use select with stopCh to prevent indefinite goroutine leak
			// when semaphore is full and service is shutting down.
			select {
			case s.sendSem <- struct{}{}:
				defer func() { <-s.sendSem }()
				s.send(evt)
			case <-s.stopCh:
				return
			}
		}()
	})
	s.mu.Lock()
	s.unsubscribe = unsub
	s.mu.Unlock()
}

// Stop unsubscribes from the event bus and waits for in-flight deliveries.
// M-29: Waits up to 15 seconds for in-flight sends to complete.
// H-9: Closes stopCh to unblock goroutines waiting on the semaphore.
func (s *WebhookService) Stop() {
	s.mu.Lock()
	unsub := s.unsubscribe
	s.unsubscribe = nil
	s.mu.Unlock()

	if unsub != nil {
		unsub()
	}

	// H-9: Signal goroutines blocked on semaphore acquisition to abort.
	close(s.stopCh)

	// Wait for in-flight sends with timeout.
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
	}
}

func (s *WebhookService) send(evt event.Event) {
	payload := WebhookPayload{
		Type:           evt.Type,
		Source:         evt.Source,
		Severity:       evt.Severity.String(),
		Timestamp:      evt.Timestamp,
		RequiresAction: evt.RequiresAction,
		Payload:        evt.Payload,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		s.logger.Warn("webhook: failed to marshal payload", "error", err)
		return
	}

	req, err := http.NewRequestWithContext(context.Background(), "POST", s.url, bytes.NewReader(body))
	if err != nil {
		s.logger.Warn("webhook: failed to create request", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "SentinelGate-Webhook/1.0")

	if s.secret != "" {
		mac := hmac.New(sha256.New, []byte(s.secret))
		if _, err := mac.Write(body); err != nil {
			s.logger.Warn("webhook: hmac write failed", "error", err)
			return
		}
		sig := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Signature-256", "sha256="+sig)
	}

	// Read client under lock to avoid race with SetHTTPClient.
	s.mu.Lock()
	client := s.client
	s.mu.Unlock()

	resp, err := client.Do(req)
	if err != nil {
		s.logger.Warn("webhook: delivery failed", "url", redactURL(s.url), "event", evt.Type, "error", err)
		return
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
	}()

	if resp.StatusCode >= 400 {
		s.logger.Warn("webhook: endpoint returned error", "url", redactURL(s.url), "event", evt.Type, "status", resp.StatusCode)
	}
}

// redactURL removes userinfo (credentials) from a URL for safe logging (L-65).
func redactURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "<invalid-url>"
	}
	if u.User != nil {
		u.User = url.UserPassword("***", "***")
	}
	return u.String()
}
