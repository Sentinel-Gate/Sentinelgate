//go:build race

package integration

import "time"

// perfP99Threshold is the maximum acceptable p99 latency with the race detector.
// The race detector adds ~5-10x overhead. Set conservatively for CI stability.
var perfP99Threshold = 50 * time.Millisecond

// perfP50Threshold is the maximum acceptable p50 latency with the race detector.
var perfP50Threshold = 20 * time.Millisecond
