package nikto

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/odyssey/shieldscan-engine/internal/events"
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
// nikto_headers.plugin in full; 999100 and 011799 are the only
// observation-only ones.
//
// Driven through resolveItem rather than classify, because classify is
// now only the first of three resolution steps and asserting on it
// alone would stop covering the path production takes. 999986 is the
// case in point: it no longer has an entry in `classifications` at all.
func TestClassify_RealFindingsAreKept(t *testing.T) {
	cases := []struct{ id, desc, want string }{
		{"999976", "The anti-clickjacking X-Frame-Options header is not present.", "nikto-missing-xfo"},
		{"999978", "X-Frame-Options header is set to allow framing from example.com.", "nikto-permissive-xfo"},
		{"999979", `RFC-1918 IP address found in the 'location' header. The IP is "10.0.0.1".`, "nikto-internal-ip-in-header"},
		{"999984", "Server leaks inodes via ETags, header found with file /, fields: 0xW/124fa 0x1a0016977d3", "nikto-etag-inode-leak"},
		{"999986", "Retrieved x-powered-by header: Express", "nikto-disclosed-header-x-powered-by"},
	}
	for _, c := range cases {
		t.Run(c.want, func(t *testing.T) {
			cl := resolveItem(c.id, c.desc)
			require.NotEmpty(t, cl.slug, "%s must resolve", c.id)
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
//
// The id below is deliberately one that belongs to NEITHER family — not
// a curated plugin class, and absent from the generated db_tests table.
// This test used to use 001675, which was a fair example of "unknown"
// when every db test was unknown; it is now nikto-interesting-file, and
// TestResolveItem_DBTestIDsResolveByCategory covers that.
func TestFindingTypeFor_UnknownItemKeepsTheRawID(t *testing.T) {
	const unmapped = "999001" // plugin-id shape, no curated class
	_, inTable := dbTestTuning[unmapped]
	require.False(t, inTable, "fixture must be an id neither family claims")

	assert.Equal(t, "nikto-"+unmapped,
		findingTypeFor(unmapped, "Some message Nikto has not shown us before."))
}

// ─── 999986 disclosed headers ────────────────────────────────────────

// TestDisclosedHeaders_DoNotShareAFingerprint is the regression guard
// for a live defect, and it is deliberately written as a FINGERPRINT
// assertion rather than a FindingType one.
//
// 999986 had a single curated class with the marker "Retrieved ", which
// matched every header the plugin reports. ComputeFingerprint hashes
// FindingType and TargetURL but not Description, and these findings all
// carry the site root as their uri — so every disclosed header on a
// host collapsed into one row. Measured on a live scan: "Retrieved via
// header: 1.1 Caddy" and "Retrieved access-control-allow-origin header:
// *" both hashed to 81ce4b48d135.
//
// Asserting on FindingType alone would have passed against the old
// code's intent and missed the point. The property that matters is that
// two findings differing only in their message end up as two findings.
func TestDisclosedHeaders_DoNotShareAFingerprint(t *testing.T) {
	const site = "https://example.com:443"
	mk := func(desc string) events.RawFinding {
		f := itemToFinding(
			niktoItem{ID: disclosedHeaderID, Description: desc, URI: "/"},
			niktoScanDetails{SiteName: site},
			trimRootPathPrefix(desc))
		f.ToolName = "nikto"
		f.Fingerprint = tools.ComputeFingerprint(f)
		return f
	}

	via := mk("/: Retrieved via header: 1.1 Caddy.")
	cors := mk("/: Retrieved access-control-allow-origin header: *.")

	assert.Equal(t, "nikto-disclosed-header-via", via.FindingType)
	assert.Equal(t, "nikto-disclosed-header-access-control-allow-origin", cors.FindingType)
	assert.Equal(t, via.TargetURL, cors.TargetURL, "both are reported against the site root")
	assert.NotEqual(t, via.Fingerprint, cors.Fingerprint,
		"two different disclosed headers on one URL must be two findings")
}

// TestDisclosedHeaders_MarkersAreUnambiguous guards the anchoring.
// Several header names are substrings of others (server-name inside
// x-server-name, x-ip inside x-real-ip), so a bare name match would
// make classification depend on list order. The "Retrieved "/" header"
// anchors are what prevent that, and this asserts the property over the
// whole list rather than over the two examples above.
func TestDisclosedHeaders_MarkersAreUnambiguous(t *testing.T) {
	for _, h := range disclosedHeaders {
		desc := "/: " + disclosedHeaderMarker(h) + ": some-value"
		slug, ok := classifyDisclosedHeader(disclosedHeaderID, desc)
		require.True(t, ok, "header %q must classify", h)
		assert.Equal(t, "disclosed-header-"+h, slug,
			"header %q matched another entry's marker", h)
	}
	assert.Len(t, disclosedHeaders, 53,
		"transcribed from nikto_headers.plugin's @interesting_headers; "+
			"a change here should be a deliberate re-read of that list")
}

// A header Nikto adds to its list must surface as unclassified — raw id
// plus the INFO log — rather than silently joining a catch-all. That
// visible signal is what the old generic marker gave up.
func TestDisclosedHeaders_UnknownHeaderFallsThrough(t *testing.T) {
	got := resolveItem(disclosedHeaderID, "/: Retrieved x-future-header header: v")
	assert.Empty(t, got.slug)
	assert.Equal(t, "nikto-"+disclosedHeaderID,
		findingTypeFor(disclosedHeaderID, "/: Retrieved x-future-header header: v"))
}

// TestCombineSiteURI_DotMeansTheSiteRoot pins the cosmetic half of the
// same fixture.
//
// Nikto uses "." as the uri for checks aimed at the server itself
// rather than at a path — the missing-X-Content-Type-Options finding is
// one — and the naive join rendered that as "https://host:443/.", which
// reached the customer. trimRootPathPrefix already treated ".: " and
// "/: " as the same thing when stripping the description prefix, so the
// two halves of the finding disagreed about what "." meant.
func TestCombineSiteURI_DotMeansTheSiteRoot(t *testing.T) {
	cases := []struct{ name, site, uri, want string }{
		{"dot is the root", "https://example.com:443", ".", "https://example.com:443/"},
		{"slash is the root", "https://example.com:443", "/", "https://example.com:443/"},
		{"trailing slash not doubled", "https://example.com:443/", "/", "https://example.com:443/"},
		{"a real path is untouched", "https://example.com:443", "/ftp/", "https://example.com:443/ftp/"},
		{"a dotfile is NOT the root", "https://example.com:443", "/.htpasswd", "https://example.com:443/.htpasswd"},
		{"relative path keeps its join", "https://example.com:443", "admin/", "https://example.com:443/admin/"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, combineSiteURI(c.site, c.uri))
		})
	}
}

// ─── db_tests category classification ────────────────────────────────

// TestResolveItem_DBTestIDsResolveByCategory pins the three ids that
// prompted this: they were arriving as nikto-001675, nikto-001811 and
// nikto-002739, opaque to a customer and unmappable one at a time —
// db_tests holds 6951 of them.
//
// The two "interesting file" tests share a FindingType and MUST still
// be distinct findings. That is the property to check before widening
// any FindingType, and it holds here because the path lives in
// TargetURL, which the fingerprint also hashes — unlike the 999100
// header case, where four observations shared the uri "/" and a common
// FindingType collapsed them to one identity.
func TestResolveItem_DBTestIDsResolveByCategory(t *testing.T) {
	cases := []struct {
		id, desc, wantSlug string
	}{
		{"001675", "/ftp/: This might be interesting.", "interesting-file"},
		{"001811", "/public/: This might be interesting.", "interesting-file"},
		{"002739", "/.htpasswd: Contains authorization information", "info-disclosure"},
	}
	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			got := resolveItem(c.id, c.desc)
			assert.Equal(t, c.wantSlug, got.slug)
			assert.Equal(t, "db-test", got.source)
			assert.False(t, got.drop, "a db_tests category is never a drop")
			assert.Equal(t, "nikto-"+c.wantSlug, findingTypeFor(c.id, c.desc))
		})
	}
}

// TestResolveItem_CuratedClassBeatsCategory pins the ordering. The two
// id families are disjoint in Nikto 2.5.0, so this cannot currently
// trigger — which is exactly why it is worth asserting: if a future
// Nikto moves a plugin check into db_tests under the same id, the
// hand-reviewed, message-anchored class must win over the coarse
// category rather than the answer depending on map lookup order.
func TestResolveItem_CuratedClassBeatsCategory(t *testing.T) {
	for _, c := range classifications {
		if _, collides := dbTestTuning[c.id]; collides {
			got := resolveItem(c.id, "…"+c.marker+"…")
			assert.Equal(t, "curated", got.source,
				"id %s is in both families; the curated class must win", c.id)
		}
	}
}

// TestDBTestTuning_EveryIDResolvesToExactlyOneClass is the forcing
// function over the generated table, and the reason the table can be
// regenerated safely.
//
// Three properties, each of which has a way of silently going wrong
// across a regeneration:
//
//   - Every id maps to a category character that tuningClassSlug names.
//     The generator validates against Nikto's legend; this validates
//     against OUR naming, so a category Nikto adds cannot reach
//     production as an unnamed class.
//   - The table is non-trivial. A generator that silently produced a
//     short or empty table would otherwise pass every other test here
//     while quietly returning thousands of items to raw-id identity —
//     the first draft of the generator lost 8 tests exactly that way,
//     to CSV quoting.
//   - A map literal cannot hold a duplicate key, so uniqueness is a
//     compile-time property; what is asserted instead is that nothing
//     resolves ambiguously, i.e. exactly one slug per id.
func TestDBTestTuning_EveryIDResolvesToExactlyOneClass(t *testing.T) {
	require.Greater(t, len(dbTestTuning), 6000,
		"the shipped table looks truncated: Nikto 2.5.0 has 6951 tests. "+
			"Regenerate with `go generate ./internal/tools/nikto/`")

	seen := map[string]string{}
	for id, tuning := range dbTestTuning {
		slug, named := tuningClassSlug[tuning]
		require.True(t, named,
			"test %s has tuning %q, which tuningClassSlug does not name; "+
				"Nikto added a category and it must be named before the table "+
				"is regenerated", id, string(tuning))
		require.NotEmpty(t, slug)

		got := resolveItem(id, "any description")
		assert.Equal(t, slug, got.slug, "id %s must resolve to exactly one class", id)
		seen[id] = slug
	}
	assert.Len(t, seen, len(dbTestTuning))
}

// TestTuningClassSlug_CoversNiktosLegend guards the naming map against
// the other direction of drift: a class quietly deleted here would make
// every test in that category fall back to a raw id, which no other
// assertion would notice because the ids would still be in the table.
func TestTuningClassSlug_CoversNiktosLegend(t *testing.T) {
	// Nikto's documented tuning legend, from the header comment of
	// databases/db_tests (2.5.0). Transcribed, not derived, so that the
	// generated table cannot be both the source and the check.
	legend := "0123456789abcdef"
	for i := 0; i < len(legend); i++ {
		assert.Contains(t, tuningClassSlug, legend[i],
			"Nikto tuning category %q is unnamed", string(legend[i]))
	}
	assert.Len(t, tuningClassSlug, len(legend),
		"tuningClassSlug must name Nikto's categories and no others")
}

// TestResolveItem_AltSvcIsDropped pins the second drop. A server
// advertising HTTP/3 via alt-svc is current configuration, not a
// defect, and Nikto's own h3 message is the scanner reporting that it
// cannot test QUIC.
func TestResolveItem_AltSvcIsDropped(t *testing.T) {
	got := resolveItem("011799",
		"/: An alt-svc header was found which is advertising HTTP/3. "+
			"The endpoint is: ':443'. Nikto cannot test HTTP/3 over QUIC.")
	assert.True(t, got.drop)
	assert.Equal(t, "alt-svc-advertised", got.slug)

	// Message-anchored: a reworded or reused 011799 must fall through to
	// the unclassified log rather than inherit the drop. Failing toward a
	// visible spurious finding beats failing toward a silent lost one.
	reworded := resolveItem("011799", "/: Some entirely different future message.")
	assert.False(t, reworded.drop, "the drop must not be keyed on the id alone")
	assert.Empty(t, reworded.slug)
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
	require.Len(t, findings, 7,
		"9 items minus 2 observations: uncommon-header and alt-svc")

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

	// Every class 2.5.0 emitted here is mapped, and NOTHING keeps a raw
	// "nikto-<id>" form. The comment here previously called 011799 a
	// db_tests id and justified leaving it raw on that basis; it is in
	// fact a plugin id (nikto_headers.plugin:394), one of 77, and the
	// two families do not overlap. It is now dropped as an observation.
	for _, want := range []string{
		// Two headers, two identities. Under the old generic "Retrieved "
		// marker both of these were nikto-disclosed-header on the same
		// uri, which made them one row.
		"nikto-disclosed-header-via",
		"nikto-disclosed-header-access-control-allow-origin",
		"nikto-missing-hsts",
		"nikto-robots-listed-path",
		"nikto-robots-entries",
		"nikto-missing-content-type-options",
		"nikto-compression-enabled",
	} {
		assert.Contains(t, byType, want)
	}
	assert.NotContains(t, byType, "nikto-uncommon-header")
	assert.NotContains(t, byType, "nikto-alt-svc-advertised", "dropped, not reclassified")
	for ft := range byType {
		assert.NotRegexp(t, `^nikto-\d+$`, ft,
			"no finding may keep a raw numeric id: %s", ft)
	}

	// Every TargetURL must be a URL a customer would recognise. This
	// fixture carries the "." uri Nikto uses for server-level checks,
	// which used to render as ".../.".
	for _, f := range findings {
		assert.NotContains(t, f.TargetURL, ":443/.",
			"%q: Nikto's \".\" uri means the site root", f.TargetURL)
	}

	// Distinct fingerprints, end to end from the fixture — the property
	// the 999986 split exists for, asserted on parser output rather than
	// on a hand-built finding.
	fps := map[string]string{}
	for _, f := range findings {
		f.ToolName = "nikto"
		fp := tools.ComputeFingerprint(f)
		prev, dup := fps[fp]
		assert.False(t, dup, "fingerprint collision: %q and %q", prev, f.Title)
		fps[fp] = f.Title
	}
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
