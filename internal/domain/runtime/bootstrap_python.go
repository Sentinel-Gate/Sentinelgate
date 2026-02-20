package runtime

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
)

//go:embed python/sitecustomize.py
var pythonSitecustomize []byte

// WritePythonBootstrap writes the embedded sitecustomize.py to the given directory.
// The directory must already exist.
func WritePythonBootstrap(dir string) error {
	dest := filepath.Join(dir, "sitecustomize.py")
	if err := os.WriteFile(dest, pythonSitecustomize, 0644); err != nil {
		return fmt.Errorf("failed to write sitecustomize.py: %w", err)
	}
	return nil
}
