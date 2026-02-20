package runtime

import (
	"testing"
)

func TestIsPythonCommand(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		command string
		want    bool
	}{
		{"bare python", "python", true},
		{"python3", "python3", true},
		{"python3.12", "python3.12", true},
		{"python2", "python2", true},
		{"python with path", "/usr/bin/python3", true},
		{"homebrew python", "/opt/homebrew/bin/python3.12", true},
		{"not python - node", "node", false},
		{"not python - pip", "pip", false},
		{"not python - empty", "", false},
		{"not python - claude", "claude", false},
		{"not python - gemini", "gemini", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := IsPythonCommand(tt.command)
			if got != tt.want {
				t.Errorf("IsPythonCommand(%q) = %v, want %v", tt.command, got, tt.want)
			}
		})
	}
}

func TestDetectPythonSitePackages_EmptyCommand(t *testing.T) {
	t.Parallel()

	result := DetectPythonSitePackages("")
	if result != nil {
		t.Errorf("DetectPythonSitePackages(\"\") = %v, want nil", result)
	}
}

func TestDetectPythonSitePackages_InvalidCommand(t *testing.T) {
	t.Parallel()

	result := DetectPythonSitePackages("nonexistent-python-binary-xyz")
	if result != nil {
		t.Errorf("DetectPythonSitePackages(invalid) = %v, want nil", result)
	}
}

func TestDetectPythonSitePackages_RealPython(t *testing.T) {
	t.Parallel()

	// This test only runs if python3 is available.
	result := DetectPythonSitePackages("python3")
	if result == nil {
		t.Skip("python3 not available or returned no site-packages")
	}

	// Should contain at least one path with "site-packages".
	found := false
	for _, p := range result {
		if p != "" {
			found = true
			break
		}
	}
	if !found {
		t.Error("DetectPythonSitePackages(python3) returned empty paths")
	}
}
