package service

import (
	"bytes"
	"strings"
	"testing"
)

func FuzzReadLineUnbuffered(f *testing.F) {
	// Seeds
	f.Add([]byte("hello\n"))
	f.Add([]byte("no newline"))
	f.Add([]byte("\n"))
	f.Add([]byte("line1\nline2\n"))
	f.Add([]byte{0xff, 0xfe, '\n'})
	f.Add([]byte(""))
	f.Add([]byte(strings.Repeat("a", 10000) + "\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		// Must not panic
		line, err := readLineUnbuffered(r)
		if err != nil {
			return
		}
		// If data contains \n, the result should be bytes before the first \n
		if idx := bytes.IndexByte(data, '\n'); idx >= 0 {
			if !bytes.Equal(line, data[:idx]) {
				t.Errorf("expected %q, got %q", data[:idx], line)
			}
		}
	})
}
