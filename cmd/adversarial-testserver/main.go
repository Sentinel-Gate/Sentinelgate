// Package main implements a standalone adversarial JSON-RPC 2.0 test server
// that speaks on stdin/stdout. It supports configurable misbehaviors via flags
// for testing SentinelGate's MCP proxy resilience.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// JSON-RPC types
// ---------------------------------------------------------------------------

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"` // may be number, string, or null
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   interface{} `json:"error,omitempty"`
}

type rpcNotification struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// writeJSON marshals v and writes it as a single line to stdout, then flushes.
func writeJSON(v interface{}) {
	data, err := json.Marshal(v)
	if err != nil {
		// best-effort: ignore marshal errors in a test helper
		return
	}
	os.Stdout.Write(data)
	os.Stdout.Write([]byte("\n"))
	os.Stdout.Sync()
}

// parseID returns the request ID in a form suitable for embedding back into a
// response. JSON-RPC IDs can be numbers, strings, or null.
func parseID(raw json.RawMessage) interface{} {
	if len(raw) == 0 {
		return nil
	}
	// Try number first.
	var n json.Number
	if err := json.Unmarshal(raw, &n); err == nil {
		if i, err2 := n.Int64(); err2 == nil {
			return i
		}
		if f, err2 := n.Float64(); err2 == nil {
			return f
		}
	}
	// Try string.
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	// Fallback: return nil (null id).
	return nil
}

// wrongID returns a deliberately wrong ID for the out-of-order mode.
func wrongID(id interface{}) interface{} {
	switch v := id.(type) {
	case int64:
		return v + 100
	case float64:
		return v + 100
	case string:
		return "wrong-" + v
	default:
		return "wrong-id"
	}
}

// ---------------------------------------------------------------------------
// response builders
// ---------------------------------------------------------------------------

func initResult() interface{} {
	return map[string]interface{}{
		"protocolVersion": "2025-06-18",
		"capabilities":   map[string]interface{}{"tools": map[string]interface{}{}},
		"serverInfo":     map[string]interface{}{"name": "adversarial-testserver", "version": "1.0.0"},
	}
}

func toolsListResult(tools []string) interface{} {
	list := make([]interface{}, 0, len(tools))
	for _, t := range tools {
		list = append(list, map[string]interface{}{
			"name":        t,
			"description": "Echoes input",
			"inputSchema": map[string]interface{}{"type": "object", "properties": map[string]interface{}{}},
		})
	}
	return map[string]interface{}{"tools": list}
}

func toolCallResult(name string) interface{} {
	return map[string]interface{}{
		"content": []interface{}{
			map[string]interface{}{
				"type": "text",
				"text": "tool called: " + name,
			},
		},
	}
}

func methodNotFound(id interface{}, method string) rpcResponse {
	return rpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: map[string]interface{}{
			"code":    -32601,
			"message": "Method not found: " + method,
		},
	}
}

func progressNotification(index int) rpcNotification {
	return rpcNotification{
		JSONRPC: "2.0",
		Method:  "notifications/progress",
		Params: map[string]interface{}{
			"token":    "t",
			"progress": index,
		},
	}
}

// ---------------------------------------------------------------------------
// mode handlers
// ---------------------------------------------------------------------------

func handleNormal(req rpcRequest, tools []string) {
	id := parseID(req.ID)
	switch req.Method {
	case "initialize":
		writeJSON(rpcResponse{JSONRPC: "2.0", ID: id, Result: initResult()})
	case "notifications/initialized":
		// client notification — no response required
	case "tools/list":
		writeJSON(rpcResponse{JSONRPC: "2.0", ID: id, Result: toolsListResult(tools)})
	case "tools/call":
		// extract tool name from params
		name := extractToolName(req.Params)
		writeJSON(rpcResponse{JSONRPC: "2.0", ID: id, Result: toolCallResult(name)})
	default:
		// If the message has an ID it's a request; respond with error.
		// If it has no ID it's a notification; ignore.
		if len(req.ID) > 0 && string(req.ID) != "null" {
			writeJSON(methodNotFound(id, req.Method))
		}
	}
}

func extractToolName(params json.RawMessage) string {
	var p struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(params, &p); err == nil && p.Name != "" {
		return p.Name
	}
	return "unknown"
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	mode := flag.String("mode", "normal", "Server behavior mode")
	delayMs := flag.Int("delay-ms", 0, "Delay in ms before each response (mode=delay)")
	crashAfter := flag.Int("crash-after", 3, "Crash after N messages (mode=crash-after-n)")
	floodCount := flag.Int("flood-count", 5, "Notifications before real response (mode=notification-flood)")
	oversizedBytes := flag.Int("oversized-bytes", 1<<20, "Bytes without newline (mode=oversized-line)")
	toolsFlag := flag.String("tools", "echo_tool", "Comma-separated tool names to register")
	flag.Parse()

	tools := strings.Split(*toolsFlag, ",")
	for i := range tools {
		tools[i] = strings.TrimSpace(tools[i])
	}

	scanner := bufio.NewScanner(os.Stdin)
	// Allow up to 10 MB lines to avoid scanner buffer issues with large inputs.
	scanner.Buffer(make([]byte, 0, 10*1024*1024), 10*1024*1024)

	msgCount := 0

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		var req rpcRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			// Malformed input — skip.
			continue
		}

		msgCount++

		switch *mode {

		// ---------------------------------------------------------------
		case "normal":
			handleNormal(req, tools)

		// ---------------------------------------------------------------
		case "delay":
			if *delayMs > 0 {
				time.Sleep(time.Duration(*delayMs) * time.Millisecond)
			}
			handleNormal(req, tools)

		// ---------------------------------------------------------------
		case "crash-after-n":
			if msgCount > *crashAfter {
				os.Exit(1)
			}
			handleNormal(req, tools)

		// ---------------------------------------------------------------
		case "no-init-response":
			if req.Method == "initialize" {
				// Block forever — never respond.
				select {}
			}
			handleNormal(req, tools)

		// ---------------------------------------------------------------
		case "notification-flood":
			// Send flood-count notifications, then the real response.
			for i := 0; i < *floodCount; i++ {
				writeJSON(progressNotification(i))
			}
			handleNormal(req, tools)

		// ---------------------------------------------------------------
		case "notifications-before-init":
			if req.Method == "initialize" {
				writeJSON(progressNotification(0))
				writeJSON(progressNotification(1))
			}
			handleNormal(req, tools)

		// ---------------------------------------------------------------
		case "out-of-order":
			id := parseID(req.ID)
			wid := wrongID(id)
			switch req.Method {
			case "initialize":
				writeJSON(rpcResponse{JSONRPC: "2.0", ID: wid, Result: initResult()})
			case "notifications/initialized":
				// no response
			case "tools/list":
				writeJSON(rpcResponse{JSONRPC: "2.0", ID: wid, Result: toolsListResult(tools)})
			case "tools/call":
				name := extractToolName(req.Params)
				writeJSON(rpcResponse{JSONRPC: "2.0", ID: wid, Result: toolCallResult(name)})
			default:
				if len(req.ID) > 0 && string(req.ID) != "null" {
					writeJSON(methodNotFound(wid, req.Method))
				}
			}

		// ---------------------------------------------------------------
		case "partial-line":
			id := parseID(req.ID)
			var resp rpcResponse
			switch req.Method {
			case "initialize":
				resp = rpcResponse{JSONRPC: "2.0", ID: id, Result: initResult()}
			case "notifications/initialized":
				continue
			case "tools/list":
				resp = rpcResponse{JSONRPC: "2.0", ID: id, Result: toolsListResult(tools)}
			case "tools/call":
				name := extractToolName(req.Params)
				resp = rpcResponse{JSONRPC: "2.0", ID: id, Result: toolCallResult(name)}
			default:
				if len(req.ID) > 0 && string(req.ID) != "null" {
					resp = methodNotFound(id, req.Method)
				} else {
					continue
				}
			}
			data, _ := json.Marshal(resp)
			half := len(data) / 2
			os.Stdout.Write(data[:half])
			os.Stdout.Sync()
			time.Sleep(500 * time.Millisecond)
			os.Stdout.Write(data[half:])
			os.Stdout.Write([]byte("\n"))
			os.Stdout.Sync()

		// ---------------------------------------------------------------
		case "oversized-line":
			// Write oversized-bytes of 'A' without newline, then close.
			chunk := make([]byte, *oversizedBytes)
			for i := range chunk {
				chunk[i] = 'A'
			}
			os.Stdout.Write(chunk)
			os.Stdout.Sync()
			os.Exit(0)

		// ---------------------------------------------------------------
		case "close-mid-response":
			id := parseID(req.ID)
			// Build a valid response, then write it without the closing brace.
			resp := rpcResponse{JSONRPC: "2.0", ID: id, Result: initResult()}
			data, _ := json.Marshal(resp)
			// Strip trailing '}' to produce invalid JSON.
			partial := data[:len(data)-1]
			os.Stdout.Write(partial)
			os.Stdout.Sync()
			os.Exit(0)

		// ---------------------------------------------------------------
		case "slow-init":
			if req.Method == "initialize" {
				time.Sleep(35 * time.Second)
			}
			handleNormal(req, tools)

		// ---------------------------------------------------------------
		case "error-init":
			if req.Method == "initialize" {
				id := parseID(req.ID)
				writeJSON(rpcResponse{
					JSONRPC: "2.0",
					ID:      id,
					Error: map[string]interface{}{
						"code":    -32603,
						"message": "initialization failed",
					},
				})
			} else {
				handleNormal(req, tools)
			}

		// ---------------------------------------------------------------
		default:
			fmt.Fprintf(os.Stderr, "unknown mode: %s\n", *mode)
			os.Exit(2)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "scanner error: %v\n", err)
		os.Exit(1)
	}
}
