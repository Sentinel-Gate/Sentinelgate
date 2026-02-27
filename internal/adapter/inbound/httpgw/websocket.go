package httpgw

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/Sentinel-Gate/Sentinelgate/internal/domain/action"
)

// WebSocket frame opcodes (RFC 6455 Section 5.2).
const (
	wsOpText   byte = 0x1
	wsOpBinary byte = 0x2
	wsOpClose  byte = 0x8
	wsOpPing   byte = 0x9
	wsOpPong   byte = 0xA
)

// WebSocketProxy handles WebSocket upgrade requests by hijacking the client
// connection, dialing the upstream, performing the handshake, and relaying
// frames bidirectionally with per-frame content inspection.
type WebSocketProxy struct {
	scanner *action.ResponseScanner
	mode    func() action.ScanMode // closure reading atomic value
	enabled func() bool            // closure reading atomic bool
	logger  *slog.Logger
}

// NewWebSocketProxy creates a new WebSocketProxy.
func NewWebSocketProxy(
	scanner *action.ResponseScanner,
	modeGetter func() action.ScanMode,
	enabledGetter func() bool,
	logger *slog.Logger,
) *WebSocketProxy {
	return &WebSocketProxy{
		scanner: scanner,
		mode:    modeGetter,
		enabled: enabledGetter,
		logger:  logger,
	}
}

// Proxy upgrades the client connection to WebSocket and relays frames
// bidirectionally to the upstream at destURL. It hijacks the incoming
// connection, dials the upstream, forwards the WebSocket upgrade handshake,
// then starts two goroutines for bidirectional frame relay with inspection.
func (ws *WebSocketProxy) Proxy(w http.ResponseWriter, r *http.Request, destURL string) error {
	ws.logger.Info("websocket proxy started", "dest", destURL, "client", r.RemoteAddr)

	// Hijack the client connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return fmt.Errorf("ResponseWriter does not support Hijack")
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return fmt.Errorf("failed to hijack client connection: %w", err)
	}

	// Dial the upstream using SSRF-safe dialer to block connections to private IPs.
	// This prevents WebSocket connections to loopback, RFC-1918, link-local, and
	// cloud metadata addresses (e.g. 169.254.169.254).
	upstreamAddr := destURLToAddr(destURL)
	dialer := safeDialContext()
	upstreamConn, err := dialer(r.Context(), "tcp", upstreamAddr)
	if err != nil {
		// Send error back to client before closing
		_, _ = clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		clientConn.Close()
		return fmt.Errorf("failed to dial upstream %s: %w", upstreamAddr, err)
	}

	// Send the WebSocket upgrade request to upstream
	upstreamPath := destURLToPath(destURL)
	upgradeReq := buildUpgradeRequest(r, upstreamPath)
	if _, err := upstreamConn.Write([]byte(upgradeReq)); err != nil {
		clientConn.Close()
		upstreamConn.Close()
		return fmt.Errorf("failed to send upgrade to upstream: %w", err)
	}

	// Read the upgrade response using proper HTTP parsing.
	// A single Read() call may not capture the full HTTP response headers, and
	// substring matching ("101") is unreliable. bufio.Reader + http.ReadResponse
	// handles partial reads correctly and validates the status code.
	upstreamBuf := bufio.NewReader(upstreamConn)
	upstreamResp, err := http.ReadResponse(upstreamBuf, nil)
	if err != nil {
		clientConn.Close()
		upstreamConn.Close()
		return fmt.Errorf("failed to read upgrade response: %w", err)
	}

	if upstreamResp.StatusCode != http.StatusSwitchingProtocols {
		// Forward the non-101 error response to the client verbatim.
		var respBytes bytes.Buffer
		_ = upstreamResp.Write(&respBytes)
		_, _ = clientConn.Write(respBytes.Bytes())
		clientConn.Close()
		upstreamConn.Close()
		return fmt.Errorf("upstream did not return 101: got %d", upstreamResp.StatusCode)
	}

	// Serialize the 101 response and forward it to the client.
	var switchBuf bytes.Buffer
	if err := upstreamResp.Write(&switchBuf); err != nil {
		clientConn.Close()
		upstreamConn.Close()
		return fmt.Errorf("failed to serialize upgrade response: %w", err)
	}
	if _, err := clientConn.Write(switchBuf.Bytes()); err != nil {
		clientConn.Close()
		upstreamConn.Close()
		return fmt.Errorf("failed to forward upgrade response to client: %w", err)
	}

	// After http.ReadResponse, upstreamBuf may have buffered bytes that arrived
	// together with the HTTP headers (e.g. early WebSocket frames from the server).
	// Use io.MultiReader so those buffered bytes are replayed before the raw conn.
	var upstreamReader io.Reader
	if upstreamBuf.Buffered() > 0 {
		upstreamReader = io.MultiReader(upstreamBuf, upstreamConn)
	} else {
		upstreamReader = upstreamConn
	}

	// Start bidirectional relay
	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Upstream: client frames are masked (RFC 6455)
	go func() {
		defer wg.Done()
		ws.relayFrames(clientConn, upstreamConn, true, "client->upstream")
		// Signal the other direction to stop
		_ = writeCloseFrame(upstreamConn, true)
	}()

	// Upstream -> Client: server frames are NOT masked.
	// Use upstreamReader (may include buffered bytes from the bufio.Reader).
	go func() {
		defer wg.Done()
		ws.relayFramesReader(upstreamReader, clientConn, false, "upstream->client")
		// Signal the other direction to stop
		_ = writeCloseFrame(clientConn, false)
	}()

	wg.Wait()
	clientConn.Close()
	upstreamConn.Close()

	ws.logger.Debug("websocket proxy closed", "dest", destURL)
	return nil
}

// relayFrames reads frames from src (net.Conn), inspects them, and writes to dst.
// outMasked controls whether the written frames should be masked.
func (ws *WebSocketProxy) relayFrames(src, dst net.Conn, outMasked bool, direction string) {
	ws.relayFramesReader(src, dst, outMasked, direction)
}

// relayFramesReader reads frames from src (io.Reader), inspects them, and writes to dst.
// This variant accepts io.Reader so it can work with an io.MultiReader that replays
// bytes buffered by bufio.Reader (used after http.ReadResponse on the upstream connection).
func (ws *WebSocketProxy) relayFramesReader(src io.Reader, dst net.Conn, outMasked bool, direction string) {
	for {
		opcode, payload, err := readFrame(src)
		if err != nil {
			if err != io.EOF {
				ws.logger.Debug("websocket read error", "direction", direction, "error", err)
			}
			return
		}

		// Handle close frame
		if opcode == wsOpClose {
			_ = writeFrame(dst, wsOpClose, payload, outMasked)
			return
		}

		// Handle ping/pong: forward as-is
		if opcode == wsOpPing || opcode == wsOpPong {
			if err := writeFrame(dst, opcode, payload, outMasked); err != nil {
				ws.logger.Debug("websocket write error", "direction", direction, "opcode", opcode, "error", err)
				return
			}
			continue
		}

		// Inspect the frame
		if blocked := ws.inspectFrame(opcode, payload, direction); blocked {
			// In enforce mode, send close frame and stop
			_ = writeCloseFrame(dst, outMasked)
			return
		}

		// Forward the frame
		if err := writeFrame(dst, opcode, payload, outMasked); err != nil {
			ws.logger.Debug("websocket write error", "direction", direction, "error", err)
			return
		}
	}
}

// inspectFrame inspects a WebSocket frame for prompt injection.
// Returns true if the frame should be blocked (enforce mode + detection).
func (ws *WebSocketProxy) inspectFrame(opcode byte, payload []byte, direction string) bool {
	if !ws.enabled() || ws.scanner == nil {
		return false
	}

	switch opcode {
	case wsOpText:
		content := string(payload)

		// Try JSON-first, then text fallback
		var scanResult action.ScanResult
		if json.Valid(payload) {
			scanResult = ws.scanner.Scan(content)
		} else {
			scanResult = ws.scanner.Scan(content)
		}

		if !scanResult.Detected {
			return false
		}

		// Build pattern names for logging
		patternNames := make([]string, 0, len(scanResult.Findings))
		for _, f := range scanResult.Findings {
			patternNames = append(patternNames, f.PatternName)
		}

		mode := ws.mode()
		ws.logger.Warn("websocket content scanning: prompt injection detected",
			"direction", direction,
			"mode", string(mode),
			"findings_count", len(scanResult.Findings),
			"pattern_names", strings.Join(patternNames, ","),
		)

		if mode == action.ScanModeEnforce {
			return true // Block
		}
		// Monitor mode: log and pass through
		return false

	case wsOpBinary:
		// Hash and log binary frames
		hash := sha256.Sum256(payload)
		ws.logger.Debug("websocket binary frame",
			"hash", hex.EncodeToString(hash[:]),
			"size", len(payload),
		)
		return false // Never block binary frames

	default:
		return false
	}
}

// readFrame reads a single WebSocket frame from r.
// It handles the WebSocket framing protocol: header, extended length,
// masking, and payload (RFC 6455 Section 5.2).
// The parameter is io.Reader (not net.Conn) so it can be used with
// bufio.Reader or io.MultiReader in addition to raw connections.
func readFrame(r io.Reader) (opcode byte, payload []byte, err error) {
	// Read 2-byte header
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}

	opcode = header[0] & 0x0F
	masked := (header[1] & 0x80) != 0
	payloadLen := uint64(header[1] & 0x7F)

	// Extended length
	switch payloadLen {
	case 126:
		ext := make([]byte, 2)
		if _, err := io.ReadFull(r, ext); err != nil {
			return 0, nil, err
		}
		payloadLen = uint64(binary.BigEndian.Uint16(ext))
	case 127:
		ext := make([]byte, 8)
		if _, err := io.ReadFull(r, ext); err != nil {
			return 0, nil, err
		}
		payloadLen = binary.BigEndian.Uint64(ext)
	}

	// Read mask key if masked
	var maskKey [4]byte
	if masked {
		if _, err := io.ReadFull(r, maskKey[:]); err != nil {
			return 0, nil, err
		}
	}

	// Read payload
	payload = make([]byte, payloadLen)
	if payloadLen > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
	}

	// Unmask if needed
	if masked {
		for i := range payload {
			payload[i] ^= maskKey[i%4]
		}
	}

	return opcode, payload, nil
}

// writeFrame writes a single WebSocket frame to the connection.
// If mask is true, it generates a random 4-byte mask key and XORs the payload.
func writeFrame(conn net.Conn, opcode byte, payload []byte, mask bool) error {
	// Build header: FIN=1, opcode
	header := []byte{0x80 | opcode, 0}

	payloadLen := len(payload)
	maskBit := byte(0)
	if mask {
		maskBit = 0x80
	}

	switch {
	case payloadLen <= 125:
		header[1] = maskBit | byte(payloadLen)
	case payloadLen <= 65535:
		header[1] = maskBit | 126
		ext := make([]byte, 2)
		binary.BigEndian.PutUint16(ext, uint16(payloadLen))
		header = append(header, ext...)
	default:
		header[1] = maskBit | 127
		ext := make([]byte, 8)
		binary.BigEndian.PutUint64(ext, uint64(payloadLen))
		header = append(header, ext...)
	}

	// Write header
	if _, err := conn.Write(header); err != nil {
		return err
	}

	// Mask and write payload
	if mask {
		maskKey := make([]byte, 4)
		if _, err := rand.Read(maskKey); err != nil {
			return fmt.Errorf("failed to generate mask key: %w", err)
		}
		if _, err := conn.Write(maskKey); err != nil {
			return err
		}
		// XOR payload with mask key
		masked := make([]byte, len(payload))
		for i := range payload {
			masked[i] = payload[i] ^ maskKey[i%4]
		}
		_, err := conn.Write(masked)
		return err
	}

	// Write unmasked payload
	if len(payload) > 0 {
		_, err := conn.Write(payload)
		return err
	}
	return nil
}

// writeCloseFrame sends a WebSocket close frame.
func writeCloseFrame(conn net.Conn, mask bool) error {
	// Normal closure status code 1000
	payload := make([]byte, 2)
	binary.BigEndian.PutUint16(payload, 1000)
	return writeFrame(conn, wsOpClose, payload, mask)
}

// destURLToAddr extracts the host:port from a WebSocket destination URL.
func destURLToAddr(destURL string) string {
	u := destURL
	scheme := "ws"

	// Remove scheme
	if strings.HasPrefix(u, "wss://") {
		scheme = "wss"
		u = u[6:]
	} else if strings.HasPrefix(u, "ws://") {
		u = u[5:]
	} else if strings.HasPrefix(u, "https://") {
		scheme = "wss"
		u = u[8:]
	} else if strings.HasPrefix(u, "http://") {
		u = u[7:]
	}

	// Extract host (remove path)
	if idx := strings.Index(u, "/"); idx != -1 {
		u = u[:idx]
	}

	// Add default port if missing
	if !strings.Contains(u, ":") {
		if scheme == "wss" {
			u += ":443"
		} else {
			u += ":80"
		}
	}

	return u
}

// destURLToPath extracts the path from a destination URL, defaulting to "/".
func destURLToPath(destURL string) string {
	u := destURL

	// Remove scheme
	if idx := strings.Index(u, "://"); idx != -1 {
		u = u[idx+3:]
	}

	// Find path start
	if idx := strings.Index(u, "/"); idx != -1 {
		return u[idx:]
	}
	return "/"
}

// buildUpgradeRequest constructs the HTTP upgrade request string to send
// to the upstream WebSocket server, copying relevant headers from the
// original client request.
func buildUpgradeRequest(r *http.Request, path string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\n", path)
	fmt.Fprintf(&b, "Host: %s\r\n", r.Host)
	b.WriteString("Connection: Upgrade\r\n")
	b.WriteString("Upgrade: websocket\r\n")

	// Copy WebSocket-specific headers from original request
	wsHeaders := []string{
		"Sec-WebSocket-Key",
		"Sec-WebSocket-Protocol",
		"Sec-WebSocket-Version",
		"Sec-WebSocket-Extensions",
	}
	for _, h := range wsHeaders {
		if v := r.Header.Get(h); v != "" {
			fmt.Fprintf(&b, "%s: %s\r\n", h, v)
		}
	}

	b.WriteString("\r\n")
	return b.String()
}
