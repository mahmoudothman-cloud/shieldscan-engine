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

// ─── Nikto 2.5.0 (task_74dc91dd) ─────────────────────────────────────
//
// Captured from the first scan a WORKING Nikto ever performed here.
// Everything below was unreachable before: 2.1.5 never got past the
// server's plain-HTTP error page, so none of these messages could
// occur. They arrived through the unclassified-item INFO log, which is
// what that log exists for.

// The parser must accept BOTH root elements. 2.1.5 makes <niktoscan>
// the root; 2.5.0 wraps it in a plural <niktoscans>. Pinning XMLName
// to the singular cost a hard parse failure —
// "expected element type <niktoscan> but have <niktoscans>" — on every
// scan the moment a working binary was installed, which no hand-written
// fixture could have revealed.
func TestParseOutput_AcceptsBothRootElements(t *testing.T) {
	singular, err := parseOutputFile(noopLog())(fixturePath(t, "nikto_basic.xml"))
	require.NoError(t, err, "2.1.5 <niktoscan> root")
	require.Len(t, singular, 1)

	plural, err := parseOutputFile(noopLog())(fixturePath(t, "nikto_250_tls.xml"))
	require.NoError(t, err, "2.5.0 <niktoscans> root")
	require.NotEmpty(t, plural, "the plural root must not parse to zero findings")
}

// The whole point of the upgrade: findings that describe the site.
func TestParseOutput_Nikto250OverTLS(t *testing.T) {
	findings, err := parseOutputFile(noopLog())(fixturePath(t, "nikto_250_tls.xml"))
	require.NoError(t, err)
	require.Len(t, findings, 8, "9 items minus 1 uncommon-header observation")

	byType := map[string][]string{}
	for _, f := range findings {
		byType[f.FindingType] = append(byType[f.FindingType], f.Title)
	}
	allTitles := strings.Join(func() (out []string) {
		for _, f := range findings {
			out = append(out, f.Title)
		}
		return
	}(), " | ")

	// Every class 2.5.0 emitted here is mapped. nikto-011799 is a
	// db_tests id, which IS a stable discriminator and correctly keeps
	// the raw form.
	for _, want := range []string{
		"nikto-disclosed-header",
		"nikto-missing-hsts",
		"nikto-robots-listed-path",
		"nikto-robots-entries",
		"nikto-missing-content-type-options",
		"nikto-compression-enabled",
		"nikto-011799",
	} {
		assert.Contains(t, byType, want)
	}
	assert.NotContains(t, byType, "nikto-uncommon-header")
	assert.NotContains(t, byType, "nikto-999100")

	// It read the real site, not an error page: Caddy is the reverse
	// proxy and /robots.txt is a real path. Neither appears on nginx's
	// "400 The plain HTTP request was sent to HTTPS port".
	assert.Contains(t, allTitles, "Caddy",
		"the reverse proxy's own header — absent from the 400 error page")
	assert.Contains(t, allTitles, "/robots.txt",
		"a real path — the error page has no paths at all")
}

// 2.5.0 prefixes descriptions with the item's path. "/" and "." mean
// "the site itself" and duplicate TargetURL; a real path is context the
// title should keep.
func TestTrimRootPathPrefix(t *testing.T) {
	assert.Equal(t, "Retrieved via header: 1.1 Caddy.",
		trimRootPathPrefix("/: Retrieved via header: 1.1 Caddy."))
	assert.Equal(t, "The X-Content-Type-Options header is not set.",
		trimRootPathPrefix(".: The X-Content-Type-Options header is not set."))
	assert.Equal(t,
		"/robots.txt: contains 1 entry which should be manually viewed.",
		trimRootPathPrefix("/robots.txt: contains 1 entry which should be manually viewed."),
		"a real path is context, not noise — stripping it leaves a sentence with no subject")
	assert.Equal(t, "No prefix at all.", trimRootPathPrefix("No prefix at all."))
}

// The two versions word the same finding differently, and 2.5.0 moved
// the robots listed-path message to its own id. Both spellings must
// classify to the same identity or a scan comparison across an upgrade
// reports every finding as new.
func TestClassify_BothVersionSpellingsAgree(t *testing.T) {
	cases := []struct{ id, desc, want string }{
		{"999996", "File/dir '/ftp/' in robots.txt returned a non-forbidden or redirect HTTP code (200)", "nikto-robots-listed-path"},
		{"999997", "/robots.txt: Entry '/ftp/' is returned a non-forbidden or redirect HTTP code (200).", "nikto-robots-listed-path"},
		{"999996", `"robots.txt" contains 1 entry which should be manually viewed.`, "nikto-robots-entries"},
		{"999996", "/robots.txt: contains 1 entry which should be manually viewed.", "nikto-robots-entries"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, findingTypeFor(c.id, c.desc), "%s: %s", c.id, c.desc)
	}
}

// buildArgs must pass a URL for a TLS target. Nikto does not infer TLS
// from the port: "-h host:443" is plain HTTP on 2.1.5 AND 2.5.0, and
// against a TLS-only server that yields the error page this whole arc
// is about.
func TestBuildArgs_TLSTargetIsPassedAsAURL(t *testing.T) {
	args := buildArgs(Config{})(
		tools.Target{URL: "https://example.com/"}, tools.ScanConfig{})
	joined := strings.Join(args, " ")

	assert.Contains(t, joined, "-h https://example.com/",
		"a TLS target must keep its scheme; a bare host:443 scans plain HTTP")
	assert.NotContains(t, joined, "-h example.com:443",
		"the hostport form is exactly the Drift #71 mechanism")
}

// Plain HTTP keeps the hostport form it has always used.
func TestBuildArgs_PlainHTTPKeepsTheHostportForm(t *testing.T) {
	args := buildArgs(Config{})(
		tools.Target{URL: "http://example.com:8080/x"}, tools.ScanConfig{})
	assert.Contains(t, strings.Join(args, " "), "-h example.com:8080")
}
