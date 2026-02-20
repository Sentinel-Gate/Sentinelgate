package runtime

import (
	"testing"
)

func TestDetectFramework(t *testing.T) {
	// Not parallel: subtests with env vars use t.Setenv which requires sequential execution.

	tests := []struct {
		name     string
		command  string
		args     []string
		envVars  map[string]string
		expected string
	}{
		// --- Detection via command/args ---
		{
			name:     "langchain in args",
			command:  "python",
			args:     []string{"-m", "langchain", "serve"},
			expected: "langchain",
		},
		{
			name:     "langserve in args",
			command:  "python",
			args:     []string{"run_langserve.py"},
			expected: "langchain",
		},
		{
			name:     "langchain case insensitive",
			command:  "python",
			args:     []string{"-m", "LangChain"},
			expected: "langchain",
		},
		{
			name:     "crewai in args",
			command:  "python",
			args:     []string{"-m", "crewai", "run"},
			expected: "crewai",
		},
		{
			name:     "crewai in script path",
			command:  "python",
			args:     []string{"/app/crewai_agent.py"},
			expected: "crewai",
		},
		{
			name:     "autogen in args",
			command:  "python",
			args:     []string{"-m", "autogen"},
			expected: "autogen",
		},
		{
			name:     "autogen in script path",
			command:  "python",
			args:     []string{"/app/run_autogen_workflow.py"},
			expected: "autogen",
		},
		{
			name:     "openai agents sdk",
			command:  "python",
			args:     []string{"-m", "openai.agents"},
			expected: "openai-agents-sdk",
		},
		{
			name:     "openai swarm",
			command:  "python",
			args:     []string{"openai_swarm_demo.py"},
			expected: "openai-agents-sdk",
		},
		{
			name:     "openai without agents not detected",
			command:  "python",
			args:     []string{"-c", "import openai; openai.ChatCompletion.create()"},
			expected: "",
		},

		// --- Detection via env vars ---
		{
			name:     "langchain via LANGCHAIN_API_KEY",
			command:  "python",
			args:     []string{"app.py"},
			envVars:  map[string]string{"LANGCHAIN_API_KEY": "lc_key_123"},
			expected: "langchain",
		},
		{
			name:     "langchain via LANGCHAIN_TRACING_V2",
			command:  "python",
			args:     []string{"app.py"},
			envVars:  map[string]string{"LANGCHAIN_TRACING_V2": "true"},
			expected: "langchain",
		},
		{
			name:     "crewai via CREWAI_API_KEY",
			command:  "python",
			args:     []string{"app.py"},
			envVars:  map[string]string{"CREWAI_API_KEY": "crew_key_abc"},
			expected: "crewai",
		},
		{
			name:     "openai agents via OPENAI_AGENTS_ENDPOINT",
			command:  "python",
			args:     []string{"app.py"},
			envVars:  map[string]string{"OPENAI_AGENTS_ENDPOINT": "https://api.openai.com"},
			expected: "openai-agents-sdk",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set env vars for this test case.
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			got := DetectFramework(tt.command, tt.args)
			if got != tt.expected {
				t.Errorf("DetectFramework(%q, %v) = %q, want %q", tt.command, tt.args, got, tt.expected)
			}
		})
	}
}

func TestDetectFrameworkUnknown(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		command string
		args    []string
	}{
		{
			name:    "generic python script",
			command: "python",
			args:    []string{"app.py"},
		},
		{
			name:    "node script",
			command: "node",
			args:    []string{"index.js"},
		},
		{
			name:    "shell command",
			command: "bash",
			args:    []string{"-c", "echo hello"},
		},
		{
			name:    "empty args",
			command: "python",
			args:    nil,
		},
		{
			name:    "empty command",
			command: "",
			args:    []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := DetectFramework(tt.command, tt.args)
			if got != "" {
				t.Errorf("DetectFramework(%q, %v) = %q, want empty string", tt.command, tt.args, got)
			}
		})
	}
}
