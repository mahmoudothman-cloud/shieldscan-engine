package zap

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// validateTarget enforces Q4/Q9 lock requirements:
//   - URL scheme required (http or https)
//   - host parses as URL
//   - if allowPrivate=false: reject RFC1918 + link-local + loopback IPs
//
// Per Task 7.3 design doc §3.3 step (a) target validation. Layer 3
// defense-in-depth complementing shieldscan-api Layer 1 ownership
// validation per ADR-013.
func validateTarget(rawURL string, allowPrivate bool) error {
	if rawURL == "" {
		return errors.New("zap target: URL required")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("zap target: parse URL %q: %w", rawURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("zap target: scheme must be http or https; got %q", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("zap target: host required in URL %q", rawURL)
	}
	if allowPrivate {
		return nil
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if ip == nil {
		// Not an IP literal — DNS hostname. Phase 1 v1 accepts any
		// resolved hostname (Layer 1 ownership validation upstream
		// per ADR-013). Forward-pin: optional resolved-IP private-range
		// check at Phase 5 followup if tenant-isolation hardening warrants.
		return nil
	}
	if isPrivateOrLinkLocal(ip) {
		return fmt.Errorf("zap target: IP %s is RFC1918/link-local/loopback; set AllowPrivateTargets=true to scan", ip.String())
	}
	return nil
}

// isPrivateOrLinkLocal returns true for RFC1918, IPv4 link-local
// (169.254.0.0/16), loopback (127.0.0.0/8 + ::1), and IPv6
// link-local (fe80::/10) + unique-local (fc00::/7) ranges.
func isPrivateOrLinkLocal(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsPrivate() {
		return true
	}
	return false
}

// extractHostPort returns "host:port" suitable for ZAP's httpSessions
// site parameter (ZAP's session-store keying). Default port inferred
// from scheme when not explicit (80 for http; 443 for https).
func extractHostPort(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("zap target: parse URL %q: %w", rawURL, err)
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			return "", fmt.Errorf("zap target: cannot infer port from scheme %q", u.Scheme)
		}
	}
	return strings.ToLower(host) + ":" + port, nil
}
