package nmap

import (
	"testing"

	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateTarget_AcceptsPublicIP(t *testing.T) {
	target := tools.Target{URL: "8.8.8.8"}
	cfg := tools.ScanConfig{}
	assert.NoError(t, validateTarget(target, cfg))
}

func TestValidateTarget_AcceptsHostname(t *testing.T) {
	target := tools.Target{URL: "example.com"}
	cfg := tools.ScanConfig{}
	assert.NoError(t, validateTarget(target, cfg), "hostname targets bypass IP-level validation")
}

func TestValidateTarget_AcceptsHTTPSURL(t *testing.T) {
	target := tools.Target{URL: "https://example.com"}
	cfg := tools.ScanConfig{}
	assert.NoError(t, validateTarget(target, cfg), "scheme-prefixed hostnames pass through")
}

func TestValidateTarget_RejectsLoopbackIPv4(t *testing.T) {
	target := tools.Target{URL: "127.0.0.1"}
	cfg := tools.ScanConfig{}
	err := validateTarget(target, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "loopback")
}

func TestValidateTarget_RejectsLoopbackIPv6(t *testing.T) {
	target := tools.Target{URL: "::1"}
	cfg := tools.ScanConfig{}
	err := validateTarget(target, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "loopback")
}

func TestValidateTarget_RejectsLinkLocalCloudMetadata(t *testing.T) {
	target := tools.Target{URL: "169.254.169.254"}
	cfg := tools.ScanConfig{}
	err := validateTarget(target, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "link-local")
}

func TestValidateTarget_RejectsMulticast(t *testing.T) {
	target := tools.Target{URL: "224.0.0.1"}
	cfg := tools.ScanConfig{}
	err := validateTarget(target, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "multicast")
}

func TestValidateTarget_RejectsUnspecified(t *testing.T) {
	target := tools.Target{URL: "0.0.0.0"}
	cfg := tools.ScanConfig{}
	err := validateTarget(target, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unspecified")
}

func TestValidateTarget_RejectsRFC1918WithoutAllowPrivate(t *testing.T) {
	cases := []string{"10.0.0.1", "172.16.0.1", "192.168.1.1"}
	for _, addr := range cases {
		t.Run(addr, func(t *testing.T) {
			target := tools.Target{URL: addr}
			cfg := tools.ScanConfig{AllowPrivateTargets: false}
			err := validateTarget(target, cfg)
			require.Error(t, err, "%s should be rejected without AllowPrivateTargets", addr)
			assert.Contains(t, err.Error(), "RFC1918")
		})
	}
}

func TestValidateTarget_AcceptsRFC1918WithAllowPrivate(t *testing.T) {
	target := tools.Target{URL: "10.0.0.1"}
	cfg := tools.ScanConfig{AllowPrivateTargets: true}
	assert.NoError(t, validateTarget(target, cfg))
}

func TestValidateTarget_RejectsReservedIANA(t *testing.T) {
	cases := []struct {
		name string
		ip   string
	}{
		{"CGNAT", "100.64.0.1"},
		{"TEST-NET-1", "192.0.2.1"},
		{"TEST-NET-2", "198.51.100.1"},
		{"TEST-NET-3", "203.0.113.1"},
		{"reserved future", "240.0.0.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := tools.Target{URL: tc.ip}
			cfg := tools.ScanConfig{}
			err := validateTarget(target, cfg)
			require.Error(t, err, "%s should be rejected", tc.ip)
			assert.Contains(t, err.Error(), "reserved")
		})
	}
}

func TestValidateTarget_RejectsShieldScanInfra(t *testing.T) {
	// Use a public IP not otherwise classified; CIDR overrides the
	// public-IP accept path via the infra check ordering in
	// validateIPTarget.
	t.Setenv("SHIELDSCAN_INFRA_CIDRS", "8.8.8.0/24")
	target := tools.Target{URL: "8.8.8.8"}
	cfg := tools.ScanConfig{}
	err := validateTarget(target, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ShieldScan infrastructure")
}

func TestValidateTarget_AcceptsPublicIPWhenInfraEnvEmpty(t *testing.T) {
	t.Setenv("SHIELDSCAN_INFRA_CIDRS", "")
	target := tools.Target{URL: "8.8.8.8"}
	cfg := tools.ScanConfig{}
	assert.NoError(t, validateTarget(target, cfg))
}

func TestStripScheme(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"https://example.com", "example.com"},
		{"http://example.com", "example.com"},
		{"tcp://192.168.1.1", "192.168.1.1"},
		{"udp://example.com", "example.com"},
		{"example.com", "example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			assert.Equal(t, tc.want, stripScheme(tc.input))
		})
	}
}

func TestStripPort(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"example.com:8080", "example.com"},
		{"192.168.1.1:80", "192.168.1.1"},
		{"[::1]:8080", "::1"},
		{"::1", "::1"}, // bare IPv6 preserved (no port)
		{"example.com", "example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			assert.Equal(t, tc.want, stripPort(tc.input))
		})
	}
}

func TestValidateTarget_RejectsEmptyURL(t *testing.T) {
	target := tools.Target{URL: ""}
	cfg := tools.ScanConfig{}
	err := validateTarget(target, cfg)
	require.Error(t, err)
}

func TestValidateTarget_AllowPrivateDoesNotBypassReservedIANA(t *testing.T) {
	target := tools.Target{URL: "100.64.0.1"}
	cfg := tools.ScanConfig{AllowPrivateTargets: true}
	err := validateTarget(target, cfg)
	require.Error(t, err, "AllowPrivateTargets must not bypass reserved IANA ranges")
	assert.Contains(t, err.Error(), "reserved")
}

func TestValidateTarget_AllowPrivateDoesNotBypassLoopback(t *testing.T) {
	target := tools.Target{URL: "127.0.0.1"}
	cfg := tools.ScanConfig{AllowPrivateTargets: true}
	err := validateTarget(target, cfg)
	require.Error(t, err, "AllowPrivateTargets must not bypass loopback")
}
