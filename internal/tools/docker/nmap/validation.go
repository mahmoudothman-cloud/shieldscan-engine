package nmap

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/odyssey/shieldscan-engine/internal/tools"
)

// validateTarget rejects targets that would scan inappropriate networks.
// Layer 1 (shieldscan-api scan-job ownership validation) is required
// precondition; this function is defense-in-depth only.
//
// IP literal targets are classified against rejection categories.
// Hostname targets pass through (rely on Layer 1 trust + DNS rebinding
// mitigation forward-pinned to platform team).
func validateTarget(target tools.Target, cfg tools.ScanConfig) error {
	addr := target.URL
	if addr == "" {
		return errors.New("target URL is empty")
	}

	// Normalize to the bare host so IP classification below sees the same
	// string buildArgs puts on the command line. MUST stay identical to
	// buildArgs' normalization: if validation classifies a different string
	// than the one nmap receives, the checks below can be bypassed.
	addr = normalizeTarget(addr)

	if ip := net.ParseIP(addr); ip != nil {
		return validateIPTarget(ip, cfg)
	}

	// Hostname target; rely on Layer 1 + DNS rebinding mitigation
	return nil
}

func validateIPTarget(ip net.IP, cfg tools.ScanConfig) error {
	if ip.IsLoopback() {
		return errors.New("loopback targets not permitted")
	}
	// Multicast first: catches 224.0.0.0/4 in full, including link-local
	// multicast (224.0.0.0/24 per RFC5771) which would otherwise be
	// classified by IsLinkLocalMulticast. Cloud metadata endpoints are
	// IsLinkLocalUnicast (169.254.0.0/16), not multicast.
	if ip.IsMulticast() {
		return errors.New("multicast targets not permitted")
	}
	if ip.IsLinkLocalUnicast() {
		return errors.New("link-local targets not permitted (includes cloud metadata endpoints)")
	}
	if ip.IsUnspecified() {
		return errors.New("unspecified address (0.0.0.0) not permitted")
	}
	if isReservedIANA(ip) {
		return errors.New("reserved IANA range targets not permitted")
	}
	if isPrivate(ip) && !cfg.AllowPrivateTargets {
		return fmt.Errorf("RFC1918 private targets (%s) require explicit AllowPrivateTargets=true", ip)
	}
	if isShieldScanInfra(ip) {
		return errors.New("ShieldScan infrastructure targets not permitted")
	}
	return nil
}

// isPrivate returns true for RFC1918 private address ranges:
// 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16.
// IPv6 unique-local addresses (fc00::/7) also classified as private.
func isPrivate(ip net.IP) bool {
	for _, cidr := range privateCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// isReservedIANA returns true for IANA-reserved ranges that are not
// otherwise classified by net.IP standard methods. Excludes loopback,
// link-local, multicast, private (handled separately above).
func isReservedIANA(ip net.IP) bool {
	for _, cidr := range reservedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// isShieldScanInfra returns true if the IP is in a CIDR listed in the
// SHIELDSCAN_INFRA_CIDRS environment variable (comma-separated).
// Empty by default; operator-configured per deployment.
func isShieldScanInfra(ip net.IP) bool {
	cidrList := os.Getenv("SHIELDSCAN_INFRA_CIDRS")
	if cidrList == "" {
		return false
	}
	for _, cidrStr := range strings.Split(cidrList, ",") {
		cidrStr = strings.TrimSpace(cidrStr)
		if cidrStr == "" {
			continue
		}
		_, cidr, err := net.ParseCIDR(cidrStr)
		if err != nil {
			continue // skip malformed entries silently
		}
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// normalizeTarget reduces a target URL to the bare host/IP that Nmap
// accepts on the command line: scheme, path, and :port removed.
//
// Single source of truth for BOTH validateTarget (which classifies the
// result against the rejection categories) and buildArgs (which puts the
// result in argv). Keeping one helper is load-bearing, not tidiness: the
// original bug was validateTarget normalizing a local copy that buildArgs
// never saw, so `nmap https://host` reached argv, failed to resolve, and
// exited with zero hosts and no error. A second, subtler consequence of
// divergence is a validation bypass — see the ordering note below.
//
// Order matters:
//   - stripScheme first: stripPath would otherwise truncate "https://host"
//     at the scheme's own "//" and yield "https:".
//   - stripPath before stripPort: stripPort requires an all-digit suffix,
//     so "host:443/app" leaves afterColon="443/app" and the port survives.
func normalizeTarget(addr string) string {
	addr = stripScheme(addr)
	addr = stripPath(addr)
	addr = stripPort(addr)
	return addr
}

// stripPath removes a URL path suffix (everything from the first '/').
// Call only after stripScheme — see normalizeTarget's ordering note.
func stripPath(addr string) string {
	if idx := strings.Index(addr, "/"); idx != -1 {
		return addr[:idx]
	}
	return addr
}

// stripScheme removes URL scheme prefix (http://, https://, tcp://) if present.
// Returns the address portion suitable for net.ParseIP or hostname use.
func stripScheme(addr string) string {
	for _, scheme := range []string{"https://", "http://", "tcp://", "udp://"} {
		if strings.HasPrefix(addr, scheme) {
			return strings.TrimPrefix(addr, scheme)
		}
	}
	return addr
}

// stripPort removes :port suffix if present. Handles IPv6 brackets.
// Returns address without port suffix.
func stripPort(addr string) string {
	// Handle IPv6 with brackets: [::1]:8080 → ::1
	if strings.HasPrefix(addr, "[") {
		if end := strings.Index(addr, "]"); end != -1 {
			return addr[1:end]
		}
	}
	// IPv4 or hostname with :port — only strip if exactly one colon in
	// the input (single-colon form rules out bare IPv6, which has at
	// least two colons in any RFC4291 representation). Bracketed IPv6
	// is handled above; bare IPv6 with port is not a recognized form
	// per RFC3986 §3.2.2 and is preserved as-is.
	if strings.Count(addr, ":") == 1 {
		idx := strings.LastIndex(addr, ":")
		afterColon := addr[idx+1:]
		if allDigits(afterColon) {
			return addr[:idx]
		}
	}
	return addr
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// privateCIDRs are RFC1918 ranges + IPv6 unique-local.
var privateCIDRs = mustParseCIDRs(
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"fc00::/7",
)

// reservedCIDRs are IANA-reserved ranges that aren't classified by
// net.IP standard methods. Excludes loopback (127.0.0.0/8 — handled by
// IsLoopback), link-local (169.254.0.0/16 — IsLinkLocalUnicast),
// multicast (224.0.0.0/4 — IsMulticast), unspecified (0.0.0.0 —
// IsUnspecified). Includes:
//   - 100.64.0.0/10 (CGNAT)
//   - 192.0.0.0/24 (IETF Protocol Assignments)
//   - 192.0.2.0/24 (TEST-NET-1)
//   - 198.18.0.0/15 (benchmarking)
//   - 198.51.100.0/24 (TEST-NET-2)
//   - 203.0.113.0/24 (TEST-NET-3)
//   - 240.0.0.0/4 (reserved for future use)
var reservedCIDRs = mustParseCIDRs(
	"100.64.0.0/10",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"240.0.0.0/4",
)

func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(fmt.Sprintf("nmap: invalid CIDR in static list: %s", c))
		}
		out = append(out, n)
	}
	return out
}
