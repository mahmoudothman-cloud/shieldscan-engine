package nikto

import "strings"

// Message classification for Nikto items.
//
// Nikto's XML gives each item a numeric `id` and a free-text
// `description`. Neither alone is usable as a finding identity:
//
//   - The id is not a discriminator. 999100 is emitted for ANY response
//     header absent from Nikto's `db_headers` list, so a single id
//     covers an unbounded set of unrelated observations. 999996 covers
//     at least two distinct robots.txt messages.
//   - The description carries the actual meaning, but it embeds the
//     variable part (a header name, a path, an IP) so it cannot be an
//     identity either.
//
// That mattered because ComputeFingerprint hashes ToolName, FindingType,
// TargetURL, Parameter, CodeFile and CodeLine — NOT Description. With
// FindingType set to "nikto-"+id, four different headers observed on one
// host collapsed to a single fingerprint, and a live scan produced
// exactly that: 16 raw findings across 4 hosts reduced to 4 identities.
// Giving each a distinct title without fixing the identity would have
// been worse than leaving it alone — four titles competing for one
// fingerprint breaks scan-to-scan comparison.
//
// So FindingType is DERIVED from the id plus enough of the message to
// discriminate, and the title comes from the message text.

// classification is one recognised Nikto message class.
//
// A class matches when the item id matches AND the description contains
// the marker. Both are required: the id alone is not unique (999996),
// and the marker alone would match a future id whose meaning differs.
type classification struct {
	id     string // Nikto item id, exact match
	marker string // substring the description must contain
	slug   string // stable FindingType suffix
	drop   bool   // true = not a finding; parser discards the item
}

// uncommonHeaderMarker identifies Nikto's "Uncommon header" class.
//
// This is NOT a finding, and the plugin source is unambiguous about why
// (nikto_headers.plugin:166): it fires for every response header not
// present in Nikto's static `db_headers` list. That list ships with the
// scanner and predates the modern security headers, so a correctly
// configured server is reported as anomalous for each one it sets.
//
// Observed on a live production scan, verbatim:
//
//	Uncommon header 'strict-transport-security' found, with contents: max-age=31536000
//	Uncommon header 'x-content-type-options' found, with contents: nosniff
//	Uncommon header 'x-frame-options' found, with contents: DENY
//	Uncommon header 'referrer-policy' found, with contents: strict-origin-when-cross-origin
//
// Every one of those is Nikto noting a header the site SHOULD have. They
// became 9 of that scan's 41 vulnerabilities, each with an AI-generated
// remediation telling the customer to fix a header that was already
// correct.
//
// Matched as a prefix rather than by id alone so the drop is anchored to
// the message shape, not to a number that already means several things.
const uncommonHeaderMarker = "Uncommon header '"

// classifications is consulted in order; the first match wins.
//
// Only classes actually observed in Nikto 2.x output are listed. An
// unrecognised item keeps "nikto-"+id as its FindingType — no worse than
// the previous behaviour — and is logged, so a new class surfaces as a
// signal instead of silently joining a catch-all.
//
// Audited against nikto_headers.plugin in full. Of the classes it can
// emit, 999100 is the only one that reports an observation rather than a
// condition: 999979 (internal IP disclosed in a header), 999984 (ETag
// inode leak), 999976/999978 (clickjacking header absent / permissive)
// and 999983 + 999987-9 (Translate: source disclosure, IIS/WebLogic
// internal IP) all assert something is wrong. 999986 ("Retrieved <h>
// header:") reads like an observation but its header list is chosen for
// information disclosure — via, x-powered-by, x-aspnet-version,
// servlet-engine — so it is kept.
var classifications = []classification{
	{id: "999100", marker: uncommonHeaderMarker, slug: "uncommon-header", drop: true},

	{id: "999976", marker: "anti-clickjacking X-Frame-Options header is not present", slug: "missing-xfo"},
	{id: "999978", marker: "X-Frame-Options header is set to allow framing from", slug: "permissive-xfo"},
	{id: "999979", marker: "IP address found in the", slug: "internal-ip-in-header"},
	{id: "999984", marker: "Server leaks inodes via ETags", slug: "etag-inode-leak"},
	{id: "999986", marker: "Retrieved ", slug: "disclosed-header"},

	// 999996 carries at least two unrelated messages, which is why the
	// marker is load-bearing here rather than decorative.
	{id: "999996", marker: "in robots.txt returned a non-forbidden", slug: "robots-listed-path"},
	{id: "999996", marker: `"robots.txt" contains`, slug: "robots-entries"},
}

// classify returns the matching class for an item, and whether one was
// found. Callers treat !ok as "unrecognised": keep the raw id, log it.
func classify(id, description string) (classification, bool) {
	for _, c := range classifications {
		if c.id == id && strings.Contains(description, c.marker) {
			return c, true
		}
	}
	return classification{}, false
}

// findingTypeFor returns the stable FindingType for an item.
//
// A recognised class gets its curated slug. Anything else keeps
// "nikto-"+id: unchanged from the previous behaviour, and stable across
// scans, which is what scan comparison needs. Deriving a slug from
// arbitrary message text was rejected — Nikto rewords messages between
// versions, and a fingerprint that moves when the wording moves is worse
// than one that is merely coarse.
func findingTypeFor(id, description string) string {
	if c, ok := classify(id, description); ok {
		return "nikto-" + c.slug
	}
	return "nikto-" + id
}

// maxTitleLen bounds the derived title. RawFinding.Title is String(500)
// on the API side; 200 keeps a report line readable while leaving the
// full text in Description, which is never truncated.
const maxTitleLen = 200

// titleFor derives a human-readable title from the Nikto message.
//
// Previously Title was "nikto-"+id, identical to FindingType, so a
// customer saw a column of opaque identical ids. The message is the only
// place the meaning exists, so the title comes from it.
//
// The full message stays in Description; this is the display form.
func titleFor(description string) string {
	title := strings.Join(strings.Fields(description), " ")
	if len(title) <= maxTitleLen {
		return title
	}
	// Cut on a rune boundary — Nikto echoes server-supplied bytes and
	// slicing mid-rune would emit invalid UTF-8 into the wire event.
	cut := maxTitleLen
	for cut > 0 && !isRuneStart(title[cut]) {
		cut--
	}
	return strings.TrimRight(title[:cut], " ") + "…"
}

// isRuneStart reports whether b begins a UTF-8 sequence.
func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }
