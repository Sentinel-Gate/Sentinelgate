package runtime

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"strings"
)

// FailMode represents the behavior when the SentinelGate server is unreachable.
type FailMode string

const (
	// FailModeOpen allows actions when the server is unreachable (default).
	FailModeOpen FailMode = "open"

	// FailModeClosed denies actions when the server is unreachable.
	FailModeClosed FailMode = "closed"
)

// DefaultFailMode is the default fail mode when none is specified.
const DefaultFailMode = FailModeOpen

// DetectFramework attempts to identify the AI framework being used by examining
// the command and its arguments. This is a best-effort detection that runs on
// the Go side before the child process starts. The in-process bootstraps
// (Python/Node.js) perform more accurate detection via package imports.
//
// Supported frameworks:
//   - "langchain" — LangChain / LangServe
//   - "crewai" — CrewAI
//   - "autogen" — AutoGen
//   - "openai-agents-sdk" — OpenAI Agents SDK / Swarm
//
// Returns an empty string if no framework is detected.
func DetectFramework(command string, args []string) string {
	// Step 1: Check command and args for framework-specific entry points.
	allParts := make([]string, 0, len(args)+1)
	allParts = append(allParts, strings.ToLower(command))
	for _, arg := range args {
		allParts = append(allParts, strings.ToLower(arg))
	}

	hasOpenAI := false
	hasAgentsOrSwarm := false

	for _, part := range allParts {
		if strings.Contains(part, "langchain") || strings.Contains(part, "langserve") {
			return "langchain"
		}
		if strings.Contains(part, "crewai") {
			return "crewai"
		}
		if strings.Contains(part, "autogen") {
			return "autogen"
		}
		if strings.Contains(part, "openai") {
			hasOpenAI = true
		}
		if strings.Contains(part, "agents") || strings.Contains(part, "swarm") {
			hasAgentsOrSwarm = true
		}
	}

	if hasOpenAI && hasAgentsOrSwarm {
		return "openai-agents-sdk"
	}

	// Step 2: Check environment variables for framework hints.
	if os.Getenv("LANGCHAIN_API_KEY") != "" || os.Getenv("LANGCHAIN_TRACING_V2") != "" {
		return "langchain"
	}
	if os.Getenv("CREWAI_API_KEY") != "" {
		return "crewai"
	}

	// Check for any OPENAI_AGENTS_* env var.
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "OPENAI_AGENTS_") {
			return "openai-agents-sdk"
		}
	}

	return ""
}

// IsBunBinary checks if the given command resolves to a Bun-compiled binary
// by searching for the "Bun.env" signature in the executable file.
// Returns false if the command cannot be resolved or read.
func IsBunBinary(command string) bool {
	path, err := exec.LookPath(command)
	if err != nil {
		return false
	}
	return isBunBinaryFile(path)
}

// isBunBinaryFile reads up to 50MB of a file and checks for Bun runtime signatures.
func isBunBinaryFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	const maxRead = 50 << 20 // 50MB
	data, err := io.ReadAll(io.LimitReader(f, maxRead))
	if err != nil {
		return false
	}

	return bytes.Contains(data, []byte("Bun.env"))
}
