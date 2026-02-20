// Package http provides HTTP/Streamable HTTP transport for Sentinel Gate.
//
// This package implements inbound HTTP transport following the MCP
// Streamable HTTP specification (2025-03-26). It enables remote clients
// to connect to Sentinel Gate via HTTP/HTTPS instead of stdio.
//
// # Usage
//
// Create and start an HTTP transport:
//
//	transport := http.NewHTTPTransport(proxyService,
//	    http.WithAddr(":8080"),
//	    http.WithTLS("cert.pem", "key.pem"),
//	    http.WithAllowedOrigins([]string{"https://example.com"}),
//	    http.WithLogger(logger),
//	)
//	err := transport.Start(ctx)
//
// # Endpoints
//
// The transport exposes a single endpoint at the root path:
//
//	POST /  - Send JSON-RPC request, receive JSON-RPC response
//	GET /   - Open SSE stream for server-initiated messages
//	DELETE / - Terminate session and close SSE connections
//	OPTIONS / - CORS preflight handling
//
// # Request Headers
//
//	Authorization: Bearer <api-key>     - API key for authentication
//	Mcp-Session-Id: <session-id>        - Session identifier for stateful requests
//	Content-Type: application/json      - Required for POST requests
//
// # Response Headers
//
//	MCP-Protocol-Version: 2025-06-18    - MCP protocol version
//	Mcp-Session-Id: <session-id>        - Session identifier echoed back
//	Content-Type: application/json      - JSON-RPC response format
//
// # Security Features
//
// The transport implements several security measures:
//
//   - TLS 1.2 minimum: When HTTPS enabled via WithTLS, TLS 1.2 is enforced
//   - DNS rebinding protection: Origin header validation via WithAllowedOrigins
//   - Rate limiting: Applied via split interceptor chain (IPRateLimitInterceptor pre-auth, UserRateLimitInterceptor post-auth)
//   - API key authentication: Extracted from Authorization header for AuthInterceptor
//   - Real IP extraction: From X-Forwarded-For/X-Real-IP for rate limiting
//
// # Middleware Chain
//
// Requests pass through middleware in this order:
//
//  1. RealIPMiddleware - Extracts client IP from proxy headers
//  2. DNSRebindingProtection - Validates Origin header
//  3. APIKeyMiddleware - Extracts API key from Authorization header
//  4. Handler - Routes to POST/GET/DELETE handlers
//
// The handler then passes requests through the ProxyService's interceptor chain:
// Validation -> IPRateLimit -> Auth -> UserRateLimit -> Audit -> Policy -> Passthrough
//
// # Server-Sent Events (SSE)
//
// GET requests open an SSE stream for server-initiated messages. The stream:
//   - Requires Mcp-Session-Id header
//   - Sends "data: <json>\n\n" formatted events
//   - Supports multiple connections per session
//   - Cleanly disconnects on context cancellation or session termination
//
// # LangChain / Framework Compatibility
//
// This transport is compatible with:
//   - LangChain MCP client (via Streamable HTTP transport)
//   - Direct HTTP clients using JSON-RPC
//   - Browser-based clients with CORS support
//
// Session management via Mcp-Session-Id enables stateful interactions
// across multiple HTTP requests.
package http
