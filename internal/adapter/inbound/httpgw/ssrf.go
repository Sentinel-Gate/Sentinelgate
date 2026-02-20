// Package httpgw provides the HTTP Gateway forward proxy handler.
package httpgw

import (
	"context"
	"fmt"
	"net"
	"time"
)

// privateNetworks contains CIDR ranges that should be blocked from forward proxy
// access to prevent SSRF attacks reaching internal services.
var privateNetworks []*net.IPNet

func init() {
	cidrs := []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC 1918 private
		"172.16.0.0/12",  // RFC 1918 private
		"192.168.0.0/16", // RFC 1918 private
		"169.254.0.0/16", // Link-local (AWS/GCP metadata at 169.254.169.254)
		"::1/128",        // IPv6 loopback
		"fc00::/7",       // IPv6 unique local
		"fe80::/10",      // IPv6 link-local
	}
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("invalid CIDR in privateNetworks: " + cidr)
		}
		privateNetworks = append(privateNetworks, network)
	}
}

// isPrivateIP checks whether an IP address falls within a private/reserved range.
func isPrivateIP(ip net.IP) bool {
	for _, network := range privateNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// safeDialContext returns a DialContext function that blocks connections to
// private/reserved IP addresses. This prevents SSRF attacks where a forward
// proxy request resolves to an internal IP (localhost, AWS metadata, etc.).
//
// The check happens at connection time (after DNS resolution), which also
// prevents DNS rebinding attacks.
func safeDialContext() func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("ssrf: invalid address %q: %w", addr, err)
		}

		// Resolve the hostname to IPs
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("ssrf: DNS resolution failed for %q: %w", host, err)
		}

		// Check all resolved IPs — block if ANY is private
		for _, ip := range ips {
			if isPrivateIP(ip.IP) {
				return nil, fmt.Errorf("ssrf: blocked connection to private IP %s (resolved from %s)", ip.IP, host)
			}
		}

		// All IPs are safe — connect to the first one (pinned, no rebinding)
		if len(ips) == 0 {
			return nil, fmt.Errorf("ssrf: no IPs resolved for %q", host)
		}
		pinnedAddr := net.JoinHostPort(ips[0].IP.String(), port)
		return dialer.DialContext(ctx, network, pinnedAddr)
	}
}
