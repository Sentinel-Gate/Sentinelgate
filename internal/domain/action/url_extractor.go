package action

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// ExtractedURL represents a URL or IP:port pattern found in CanonicalAction arguments.
type ExtractedURL struct {
	// RawValue is the original string value found.
	RawValue string
	// URL is the parsed full URL (or constructed from IP:port).
	URL string
	// Domain is the domain name (empty if IP address).
	Domain string
	// IP is the IP address if directly specified (empty if domain).
	IP string
	// Port is the port number (0 if not specified, 80/443 inferred from scheme).
	Port int
	// Scheme is the protocol scheme (http, https, ws, wss, etc.).
	Scheme string
	// Path is the URL path.
	Path string
	// Source is the argument key path where found (e.g., "url", "config.endpoint").
	Source string
}

// ExtractOptions configures URL extraction behavior.
type ExtractOptions struct {
	// Base64Decode enables base64 decoding of string values before extraction.
	Base64Decode bool
	// MaxDepth is the maximum recursion depth (default 10 when 0).
	MaxDepth int
}

// ipPortRegex matches IPv4 addresses with optional port.
var ipPortRegex = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d{1,5}))?\b`)

// embeddedURLRegex matches URLs embedded in longer text.
var embeddedURLRegex = regexp.MustCompile(`https?://[^\s"'<>` + "`" + `)\]]+`)

// ExtractURLs scans a map[string]interface{} (typically CanonicalAction.Arguments)
// for URLs, IP:port patterns, and URLs embedded in text. It returns all discovered
// ExtractedURL entries, deduplicated by URL.
func ExtractURLs(args map[string]interface{}, opts ExtractOptions) []ExtractedURL {
	if opts.MaxDepth == 0 {
		opts.MaxDepth = 10
	}

	seen := make(map[string]bool)
	var results []ExtractedURL

	if args == nil {
		return []ExtractedURL{}
	}

	extractFromMap(args, "", opts, 0, seen, &results)
	return results
}

// extractFromMap recursively walks a map, extracting URLs from string values.
func extractFromMap(m map[string]interface{}, prefix string, opts ExtractOptions, depth int, seen map[string]bool, results *[]ExtractedURL) {
	if depth >= opts.MaxDepth {
		return
	}

	for key, val := range m {
		path := key
		if prefix != "" {
			path = prefix + "." + key
		}
		extractFromValue(val, path, opts, depth+1, seen, results)
	}
}

// extractFromValue dispatches extraction based on value type.
func extractFromValue(val interface{}, path string, opts ExtractOptions, depth int, seen map[string]bool, results *[]ExtractedURL) {
	if depth > opts.MaxDepth {
		return
	}

	switch v := val.(type) {
	case string:
		extractFromString(v, path, opts, seen, results)
	case map[string]interface{}:
		extractFromMap(v, path, opts, depth, seen, results)
	case []interface{}:
		for i, item := range v {
			itemPath := fmt.Sprintf("%s[%d]", path, i)
			extractFromValue(item, itemPath, opts, depth+1, seen, results)
		}
	}
	// Numbers, bools, nil - ignored
}

// extractFromString attempts to find URLs and IP:port patterns in a string value.
func extractFromString(s, source string, opts ExtractOptions, seen map[string]bool, results *[]ExtractedURL) {
	// 1. Try parsing as a complete URL with scheme and host
	if parsed := tryParseFullURL(s); parsed != nil {
		addResult(parsed, s, source, seen, results)
		return // If the whole string is a URL, don't look for embedded URLs
	}

	// 2. Try IP:port pattern on the full string (standalone)
	if ipResults := extractIPPort(s, source); len(ipResults) > 0 {
		for _, r := range ipResults {
			addResult(&r, s, source, seen, results)
		}
		// Don't return - also look for embedded URLs in text
		if len(ipResults) > 0 && !strings.Contains(s, " ") {
			return // Standalone IP:port, no need to search for embedded URLs
		}
	}

	// 3. Try embedded URLs in text
	matches := embeddedURLRegex.FindAllString(s, -1)
	for _, match := range matches {
		match = trimTrailingPunctuation(match)
		if parsed := tryParseFullURL(match); parsed != nil {
			addResult(parsed, match, source, seen, results)
		}
	}

	// 4. Look for embedded IP:port patterns not already covered by URL matches
	for _, r := range extractIPPort(s, source) {
		addResult(&r, r.RawValue, source, seen, results)
	}

	// 5. Base64 decoding (opt-in)
	if opts.Base64Decode {
		decoded, err := base64.StdEncoding.DecodeString(s)
		if err == nil && len(decoded) > 0 {
			ds := string(decoded)
			// Only recurse if decoded looks like it might contain a URL
			extractFromString(ds, source, ExtractOptions{Base64Decode: false}, seen, results)
		}
	}
}

// tryParseFullURL attempts to parse a string as a full URL with scheme and host.
// Returns nil if not a valid URL.
func tryParseFullURL(s string) *ExtractedURL {
	parsed, err := url.Parse(s)
	if err != nil {
		return nil
	}

	// Must have scheme AND host
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil
	}

	// Only accept known schemes
	scheme := strings.ToLower(parsed.Scheme)
	switch scheme {
	case "http", "https", "ws", "wss":
		// OK
	default:
		return nil
	}

	hostname := parsed.Hostname()
	portStr := parsed.Port()
	port := defaultPort(scheme)
	if portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil && p >= 1 && p <= 65535 {
			port = p
		}
	}

	result := &ExtractedURL{
		URL:    s,
		Scheme: scheme,
		Path:   parsed.Path,
		Port:   port,
	}

	// Determine if hostname is an IP or domain
	if ip := net.ParseIP(hostname); ip != nil {
		result.IP = hostname
	} else {
		result.Domain = hostname
	}

	return result
}

// extractIPPort tries to match a standalone IP:port or IP pattern.
func extractIPPort(s, source string) []ExtractedURL {
	var results []ExtractedURL

	matches := ipPortRegex.FindAllStringSubmatch(s, -1)
	for _, match := range matches {
		ip := match[1]
		if !isValidIPv4(ip) {
			continue
		}

		port := 0
		if match[2] != "" {
			p, err := strconv.Atoi(match[2])
			if err != nil || p < 1 || p > 65535 {
				continue
			}
			port = p
		}

		u := "http://" + ip
		if port > 0 {
			u = fmt.Sprintf("http://%s:%d", ip, port)
		}

		results = append(results, ExtractedURL{
			RawValue: match[0],
			URL:      u,
			IP:       ip,
			Port:     port,
			Scheme:   "http",
			Source:   source,
		})
	}

	return results
}

// addResult adds an ExtractedURL to results if not already seen (dedup by URL).
func addResult(r *ExtractedURL, rawValue, source string, seen map[string]bool, results *[]ExtractedURL) {
	if seen[r.URL] {
		return
	}
	seen[r.URL] = true

	r.RawValue = rawValue
	r.Source = source
	*results = append(*results, *r)
}

// isValidIPv4 checks that each octet is 0-255.
func isValidIPv4(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}

// defaultPort returns the default port for a given scheme.
func defaultPort(scheme string) int {
	switch scheme {
	case "https", "wss":
		return 443
	case "http", "ws":
		return 80
	default:
		return 0
	}
}

// trimTrailingPunctuation removes trailing periods, commas, semicolons from URL matches.
func trimTrailingPunctuation(s string) string {
	return strings.TrimRight(s, ".,;:")
}
