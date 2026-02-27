package httpgw

import (
	"net"
	"testing"
)

// TestInitPrivateNetworks verifies that InitPrivateNetworks returns nil
// (all CIDRs are valid) and populates the private network list.
// Not parallel: it reads from the global privateNetworks variable that init() populates.
func TestInitPrivateNetworks(t *testing.T) {
	// Verify InitPrivateNetworks returns nil (CIDRs are all valid).
	if err := InitPrivateNetworks(); err != nil {
		t.Fatalf("InitPrivateNetworks() returned unexpected error: %v", err)
	}

	if len(privateNetworks) == 0 {
		t.Error("InitPrivateNetworks() left privateNetworks empty")
	}

	// Spot-check: loopback should still be blocked after re-init.
	loopback := net.ParseIP("127.0.0.1")
	if loopback == nil {
		t.Fatal("failed to parse loopback IP")
	}
	if !isPrivateIP(loopback) {
		t.Error("InitPrivateNetworks() should still block 127.0.0.1 after re-init")
	}
}

func TestIsPrivateIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		ip      string
		private bool
	}{
		// Private/reserved — must be blocked
		{"127.0.0.1", true},
		{"127.0.0.2", true},
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.0.1", true},
		{"192.168.255.255", true},
		{"169.254.169.254", true}, // AWS/GCP metadata
		{"169.254.0.1", true},
		{"::1", true}, // IPv6 loopback

		// Public — must be allowed
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"93.184.216.34", false},        // example.com
		{"172.32.0.1", false},           // Just outside 172.16-31 range
		{"11.0.0.1", false},             // Just outside 10.x range
		{"192.169.0.1", false},          // Just outside 192.168.x range
		{"2001:4860:4860::8888", false}, // Google DNS IPv6
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP %q", tt.ip)
			}
			got := isPrivateIP(ip)
			if got != tt.private {
				t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, got, tt.private)
			}
		})
	}
}
