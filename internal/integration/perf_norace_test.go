//go:build !race

package integration

import "time"

// perfP99Threshold is the maximum acceptable p99 latency without the race detector.
// Set conservatively to avoid flaky failures in CI environments with variable load.
var perfP99Threshold = 10 * time.Millisecond

// perfP50Threshold is the maximum acceptable p50 latency without the race detector.
var perfP50Threshold = 2 * time.Millisecond
