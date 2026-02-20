package runtime

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// DetectPythonSitePackages runs the given Python interpreter to discover its
// site-packages directories. This ensures that pip-installed packages remain
// importable when sentinel-gate injects PYTHONPATH for the bootstrap hooks.
//
// Returns an empty slice (no error) if detection fails — the child process
// will still work if site-packages happens to be on sys.path already.
func DetectPythonSitePackages(pythonCmd string) []string {
	if pythonCmd == "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	script := `
import site, os
paths = []
try:
    paths.extend(site.getsitepackages())
except (AttributeError, TypeError):
    pass
try:
    usp = site.getusersitepackages()
    if isinstance(usp, str):
        paths.append(usp)
    elif isinstance(usp, list):
        paths.extend(usp)
except (AttributeError, TypeError):
    pass
seen = set()
for p in paths:
    if p and p not in seen and os.path.isdir(p):
        seen.add(p)
        print(p)
`

	cmd := exec.CommandContext(ctx, pythonCmd, "-c", script)
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	var result []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

// IsPythonCommand returns true if the given command looks like a Python interpreter.
func IsPythonCommand(command string) bool {
	base := strings.ToLower(filepath.Base(command))

	if base == "python" {
		return true
	}
	if strings.HasPrefix(base, "python3") || strings.HasPrefix(base, "python2") {
		return true
	}
	return false
}
