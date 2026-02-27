//go:build race

package integration

import "time"

// perfP99Threshold is the maximum acceptable p99 latency with the race detector.
// The race detector adds ~5-10x overhead, so we use 25ms instead of 5ms.
var perfP99Threshold = 25 * time.Millisecond

// perfP50Threshold is the maximum acceptable p50 latency with the race detector.
var perfP50Threshold = 10 * time.Millisecond
