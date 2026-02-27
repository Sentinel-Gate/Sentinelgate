package action

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// maxBodySize is the maximum number of bytes to read from a request body.
// Bodies larger than this are truncated to prevent memory issues.
const maxBodySize = 64 * 1024 // 64KB

// HTTPNormalizer converts *http.Request to/from CanonicalAction.
// It maps HTTP requests into the universal CanonicalAction representation
// so the entire security chain evaluates HTTP requests identically to MCP requests.
type HTTPNormalizer struct{}

// Compile-time check that HTTPNormalizer implements Normalizer.
var _ Normalizer = (*HTTPNormalizer)(nil)

// NewHTTPNormalizer creates a new HTTPNormalizer.
func NewHTTPNormalizer() *HTTPNormalizer {
	return &HTTPNormalizer{}
}

// Normalize converts an *http.Request to a CanonicalAction.
// The msg parameter must be an *http.Request; other types return an error.
func (n *HTTPNormalizer) Normalize(ctx context.Context, msg interface{}) (*CanonicalAction, error) {
	req, ok := msg.(*http.Request)
	if !ok {
		return nil, fmt.Errorf("HTTPNormalizer: expected *http.Request, got %T", msg)
	}

	action := &CanonicalAction{
		Type:            ActionHTTPRequest,
		Name:            req.Method,
		Protocol:        "http",
		Gateway:         "http-gateway",
		RequestTime:     time.Now().UTC(),
		OriginalMessage: req,
		Arguments:       make(map[string]interface{}),
		Metadata:        make(map[string]interface{}),
	}

	// Populate Destination from the request URL
	n.populateDestination(req, action)

	// Include URL and path in Arguments so action_arg_contains() works for HTTP requests
	action.Arguments["url"] = action.Destination.URL
	action.Arguments["path"] = req.URL.Path

	// Set request ID from header or generate UUID
	if reqID := req.Header.Get("X-Request-Id"); reqID != "" {
		action.RequestID = reqID
	} else {
		action.RequestID = uuid.New().String()
	}

	// Merge query parameters into Arguments
	for key, values := range req.URL.Query() {
		if len(values) == 1 {
			action.Arguments[key] = values[0]
		} else {
			action.Arguments[key] = values
		}
	}

	// Parse and merge request body into Arguments
	if req.Body != nil && req.Body != http.NoBody {
		n.parseBody(req, action)
	}

	// Include headers in Arguments (excluding sensitive headers)
	headers := make(map[string]interface{})
	for key, values := range req.Header {
		normalized := http.CanonicalHeaderKey(key)
		if normalized == "Authorization" || normalized == "Proxy-Authorization" {
			continue
		}
		if len(values) == 1 {
			headers[normalized] = values[0]
		} else {
			headers[normalized] = values
		}
	}
	action.Arguments["headers"] = headers

	// Populate Metadata
	if ct := req.Header.Get("Content-Type"); ct != "" {
		action.Metadata["content_type"] = ct
	}
	if cl := req.Header.Get("Content-Length"); cl != "" {
		action.Metadata["content_length"] = cl
	}

	return action, nil
}

// populateDestination fills the Destination fields from the request URL and Host.
func (n *HTTPNormalizer) populateDestination(req *http.Request, action *CanonicalAction) {
	scheme := req.URL.Scheme
	if scheme == "" {
		scheme = "http"
	}

	// Build the full URL
	fullURL := req.URL.String()
	// If the URL doesn't have a scheme (common in server-side requests), construct it
	if req.URL.Scheme == "" && req.Host != "" {
		fullURL = scheme + "://" + req.Host + req.URL.RequestURI()
	}

	// Extract domain (hostname without port)
	domain := req.URL.Hostname()
	if domain == "" {
		// Fall back to Host header without port
		domain = req.Host
		if idx := strings.LastIndex(domain, ":"); idx != -1 {
			// Make sure it's not an IPv6 address
			if !strings.Contains(domain, "]") || strings.LastIndex(domain, ":") > strings.LastIndex(domain, "]") {
				domain = domain[:idx]
			}
		}
	}

	// Extract port
	port := 0
	if portStr := req.URL.Port(); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	} else if req.Host != "" {
		// Try extracting from Host header
		if _, hostPort, err := splitHostPort(req.Host); err == nil && hostPort != "" {
			if p, err := strconv.Atoi(hostPort); err == nil {
				port = p
			}
		}
	}
	// Default ports
	if port == 0 {
		switch scheme {
		case "https":
			port = 443
		default:
			port = 80
		}
	}

	action.Destination = Destination{
		URL:    fullURL,
		Domain: domain,
		Port:   port,
		Scheme: scheme,
		Path:   req.URL.Path,
	}
}

// splitHostPort splits a host:port string. Unlike net.SplitHostPort, it does not
// return an error for hosts without a port.
func splitHostPort(hostport string) (host, port string, err error) {
	// Handle IPv6 [host]:port
	if strings.HasPrefix(hostport, "[") {
		idx := strings.LastIndex(hostport, "]")
		if idx == -1 {
			return hostport, "", nil
		}
		host = hostport[1:idx]
		rest := hostport[idx+1:]
		if strings.HasPrefix(rest, ":") {
			port = rest[1:]
		}
		return host, port, nil
	}
	// Simple host:port
	idx := strings.LastIndex(hostport, ":")
	if idx == -1 {
		return hostport, "", nil
	}
	return hostport[:idx], hostport[idx+1:], nil
}

// parseBody reads and parses the request body based on Content-Type,
// merging the result into action.Arguments. The body is restored so it can be
// re-read by downstream handlers.
func (n *HTTPNormalizer) parseBody(req *http.Request, action *CanonicalAction) {
	// Read body with size limit
	bodyBytes, err := io.ReadAll(io.LimitReader(req.Body, maxBodySize+1))
	if err != nil {
		return
	}

	// Restore body so it can be re-read by proxy handler
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	// Truncate if over limit
	if len(bodyBytes) > maxBodySize {
		bodyBytes = bodyBytes[:maxBodySize]
	}

	if len(bodyBytes) == 0 {
		return
	}

	contentType := req.Header.Get("Content-Type")
	// Strip charset and other params from content type for matching
	if idx := strings.Index(contentType, ";"); idx != -1 {
		contentType = strings.TrimSpace(contentType[:idx])
	}

	switch contentType {
	case "application/json":
		var parsed map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &parsed); err == nil {
			for k, v := range parsed {
				action.Arguments[k] = v
			}
		} else {
			// If not a JSON object, store as raw body
			action.Arguments["body"] = string(bodyBytes)
		}

	case "application/x-www-form-urlencoded":
		values, err := url.ParseQuery(string(bodyBytes))
		if err == nil {
			for key, vals := range values {
				if len(vals) == 1 {
					action.Arguments[key] = vals[0]
				} else {
					action.Arguments[key] = vals
				}
			}
		} else {
			action.Arguments["body"] = string(bodyBytes)
		}

	default:
		action.Arguments["body"] = string(bodyBytes)
	}
}

// Denormalize converts an InterceptResult back to HTTP response info.
// For allow decisions, returns the original *http.Request (the proxy handler will forward it).
// For deny decisions, returns nil and an error with the deny reason.
func (n *HTTPNormalizer) Denormalize(action *CanonicalAction, result *InterceptResult) (interface{}, error) {
	if result.Decision == DecisionAllow {
		return action.OriginalMessage, nil
	}

	// Build error message with reason and optional help text
	errMsg := fmt.Sprintf("action denied: %s", result.Reason)
	if result.HelpText != "" {
		errMsg = fmt.Sprintf("%s (%s)", errMsg, result.HelpText)
	}

	return nil, fmt.Errorf("%s", errMsg)
}

// Protocol returns "http" indicating this normalizer handles HTTP protocol requests.
func (n *HTTPNormalizer) Protocol() string {
	return "http"
}
