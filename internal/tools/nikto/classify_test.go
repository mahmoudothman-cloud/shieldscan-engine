package nikto

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/odyssey/shieldscan-engine/internal/tools"
)

// These tests pin the three defects a live production scan surfaced
// (scan e44a052b, moreofchat.com). All three were invisible because the
// hand-written fixtures encoded assumptions real Nikto contradicts.

// ─── "Uncommon header" is not a finding ──────────────────────────────

// The class that motivated the change. Nikto emits this for any response
// header missing from its 2015-era db_headers list, so a correctly
// configured server is reported as anomalous once per security header it
// sets. All four strings are verbatim from the production scan.
func TestClassify_UncommonHeaderIsDropped(t *testing.T) {
	for _, desc := range []string{
		"Uncommon header 'strict-transport-security' found, with contents: max-age=31536000",
		"Uncommon header 'x-content-type-options' found, with contents: nosniff",
		"Uncommon header 'x-frame-options' found, with contents: DENY",
		"Uncommon header 'referrer-policy' found, with contents: strict-origin-when-cross-origin",
		// From a real scan of a different app — the class is not limited
		// to security headers, which is the point: it is an observation.
		"Uncommon header 'x-recruiting' found, with contents: /#/jobs",
	} {
		t.Run(desc[:40], func(t *testing.T) {
			c, ok := classify("999100", desc)
			require.True(t, ok, "999100 must be a recognised class")
			assert.True(t, c.drop,
				"Nikto noting a header the site sets is not a finding")
		})
	}
}

// Over-filtering guard, the sibling of the sslyze fix's
// VulnerableResultsStillEmit. The drop must be anchored to the message
// shape, so a future 999100 that says something else still emits.
func TestClassify_DropIsAnchoredToTheMessageNotTheID(t *testing.T) {
	_, ok := classify("999100", "Some future message under a reused id")
	assert.False(t, ok,
		"an unrecognised message under 999100 must fall through to the "+
			"raw-id path, not inherit the drop")
}

// The classes that DO assert a condition must survive. Audited against
// nikto_headers.plugin in full; 999100 is the only observation-only one.
func TestClassify_RealFindingsAreKept(t *testing.T) {
	cases := []struct{ id, desc, want string }{
		{"999976", "The anti-clickjacking X-Frame-Options header is not present.", "nikto-missing-xfo"},
		{"999978", "X-Frame-Options header is set to allow framing from example.com.", "nikto-permissive-xfo"},
		{"999979", `RFC-1918 IP address found in the 'location' header. The IP is "10.0.0.1".`, "nikto-internal-ip-in-header"},
		{"999984", "Server leaks inodes via ETags, header found with file /, fields: 0xW/124fa 0x1a0016977d3", "nikto-etag-inode-leak"},
		{"999986", "Retrieved x-powered-by header: Express", "nikto-disclosed-header"},
	}
	for _, c := range cases {
		t.Run(c.want, func(t *testing.T) {
			cl, ok := classify(c.id, c.desc)
			require.True(t, ok)
			assert.False(t, cl.drop, "%s asserts a real condition", c.id)
			assert.Equal(t, c.want, findingTypeFor(c.id, c.desc))
		})
	}
}

// ─── finding_type discriminates; title is readable ───────────────────

// The identity defect. ComputeFingerprint hashes FindingType and not
// Description, so one id covering several messages collapses them to a
// single fingerprint. 999996 carries two unrelated messages and is the
// case that proves the marker is load-bearing rather than decorative.
func TestFindingTypeFor_OneIDWithTwoMeaningsGetsTwoIdentities(t *testing.T) {
	listed := findingTypeFor("999996",
		"File/dir '/ftp/' in robots.txt returned a non-forbidden or redirect HTTP code (200)")
	entries := findingTypeFor("999996",
		`"robots.txt" contains 1 entry which should be manually viewed.`)

	assert.Equal(t, "nikto-robots-listed-path", listed)
	assert.Equal(t, "nikto-robots-entries", entries)
	assert.NotEqual(t, listed, entries,
		"two meanings under one id must not share a fingerprint")
}

// An unrecognised item keeps the raw id. Stability matters more than
// precision here: a slug derived from message text would move whenever
// Nikto rewords a message, and a fingerprint that moves breaks
// scan-to-scan comparison.
func TestFindingTypeFor_UnknownItemKeepsTheRawID(t *testing.T) {
	assert.Equal(t, "nikto-001675",
		findingTypeFor("001675", "/ftp/: This might be interesting..."))
}

// Title used to be "nikto-"+id, identical to FindingType, so a customer
// saw a column of identical opaque identifiers.
func TestTitleFor_UsesTheMessage(t *testing.T) {
	title := titleFor("The anti-clickjacking X-Frame-Options header is not present.")
	assert.Equal(t, "The anti-clickjacking X-Frame-Options header is not present.", title)
	assert.NotContains(t, title, "nikto-")
}

// Nikto echoes server-supplied bytes, so the cap must not split a rune
// and put invalid UTF-8 on the wire.
func TestTitleFor_CapsOnARuneBoundary(t *testing.T) {
	long := "Server said: " + strings.Repeat("é", 300)
	title := titleFor(long)

	assert.LessOrEqual(t, len(title), maxTitleLen+len("…"))
	assert.True(t, utf8ValidString(title), "title must stay valid UTF-8")
	assert.True(t, strings.HasSuffix(title, "…"))
}

func utf8ValidString(s string) bool {
	for _, r := range s {
		if r == '�' {
			return false
		}
	}
	return true
}

// ─── TLS preflight ───────────────────────────────────────────────────

// The defect underneath the other two: Nikto 2.1.5 cannot negotiate TLS,
// so every HTTPS scan described the server's plain-HTTP error page. The
// skip must be an ERROR — a silent empty result is exactly what let this
// run unnoticed for the life of the deployment.
func TestPreflight_RefusesTLSTargets(t *testing.T) {
	pf := preflight(Config{})
	for _, u := range []string{
		"https://example.com",
		"https://example.com:8443/path",
		"wss://example.com",
		"example.com:443",
	} {
		t.Run(u, func(t *testing.T) {
			err := pf(tools.Target{URL: u}, tools.ScanConfig{})
			require.Error(t, err, "a TLS target must be refused, not scanned")
			assert.True(t, errors.Is(err, ErrTLSUnsupported))
			assert.Contains(t, err.Error(), u,
				"the reason must name the target it refused")
			assert.Contains(t, err.Error(), "SHIELDSCAN_NIKTO_TLS_CAPABLE",
				"the reason must say how to lift the restriction")
		})
	}
}

// Plain HTTP is the case Nikto handles correctly and must keep running.
func TestPreflight_AllowsPlainHTTP(t *testing.T) {
	pf := preflight(Config{})
	for _, u := range []string{
		"http://example.com",
		"http://example.com:8080/",
		"example.com:8080",
		"",
	} {
		t.Run(u, func(t *testing.T) {
			assert.NoError(t, pf(tools.Target{URL: u}, tools.ScanConfig{}))
		})
	}
}

// The escape hatch has to actually work, or verifying an upgraded binary
// would need a rebuild.
func TestPreflight_TLSCapableLiftsTheRestriction(t *testing.T) {
	assert.NoError(t,
		preflight(Config{TLSCapable: true})(
			tools.Target{URL: "https://example.com"}, tools.ScanConfig{}))
}

// The runner must actually carry the preflight — wiring it into Config
// without attaching it to the NativeRunner would pass every test above
// and change nothing in production.
func TestNewNiktoRunner_AttachesPreflight(t *testing.T) {
	r := NewNiktoRunner(Config{BinaryPath: "/bin/true"}, noopLog())
	require.NotNil(t, r.Preflight, "the TLS guard must reach the runner")

	_, err := r.Run(t.Context(),
		tools.Target{URL: "https://example.com"}, tools.ScanConfig{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrTLSUnsupported),
		"Run must refuse before spawning the subprocess")
}
