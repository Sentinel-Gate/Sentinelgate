package runtime

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
)

//go:embed node/sentinelgate-hook.js
var nodeHook []byte

// WriteNodeBootstrap writes the embedded sentinelgate-hook.js to the given directory.
// The directory must already exist.
func WriteNodeBootstrap(dir string) error {
	dest := filepath.Join(dir, "sentinelgate-hook.js")
	if err := os.WriteFile(dest, nodeHook, 0644); err != nil {
		return fmt.Errorf("failed to write sentinelgate-hook.js: %w", err)
	}
	return nil
}
