//go:build !race

package integration

import "time"

// perfP99Threshold is the maximum acceptable p99 latency without the race detector.
var perfP99Threshold = 5 * time.Millisecond

// perfP50Threshold is the maximum acceptable p50 latency without the race detector.
var perfP50Threshold = 1 * time.Millisecond
