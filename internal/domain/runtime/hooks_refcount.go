package runtime

import (
	"os"
	"strconv"
	"strings"
)

// readRefcount reads the reference count from a file. Returns 0 if the file
// doesn't exist or contains invalid data.
func readRefcount(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0
	}
	return n
}

// writeRefcount writes the reference count to a file.
func writeRefcount(path string, n int) error {
	return os.WriteFile(path, []byte(strconv.Itoa(n)+"\n"), 0644)
}
