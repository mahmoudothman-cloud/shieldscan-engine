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
// Only classes actually observed in Nikto 2.x output are listed, across
// both 2.1.5 and 2.5.0 — the two versions word several messages
// differently, and 2.5.0 prefixes every description with the item's own
// uri (stripped in parse.go before classification). Markers are matched
// with Contains rather than HasPrefix for exactly that reason. An
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

	// 011799 is the second drop, and for the same reason as 999100: it
	// reports a normal configuration rather than a defect. It fires when
	// a server advertises a protocol via the alt-svc header
	// (nikto_headers.plugin:390), which for a modern site means HTTP/3 —
	// and Nikto's own message for the h3 case is "Nikto cannot test
	// HTTP/3 over QUIC", i.e. the finding is the scanner reporting its
	// own limitation. Reporting that to a customer as a vulnerability
	// tells them their up-to-date server is a problem.
	//
	// Anchored on the message, not the id alone, so that if 011799 is
	// ever reworded or reused the item falls through to the
	// unclassified-item log rather than silently inheriting the drop.
	// That is the direction to fail in: a spurious finding is visible
	// and fixable, a silently dropped real one is neither.
	{id: "011799", marker: "alt-svc header was found which is advertising", slug: "alt-svc-advertised", drop: true},

	{id: "999976", marker: "anti-clickjacking X-Frame-Options header is not present", slug: "missing-xfo"},
	{id: "999978", marker: "X-Frame-Options header is set to allow framing from", slug: "permissive-xfo"},
	{id: "999979", marker: "IP address found in the", slug: "internal-ip-in-header"},
	{id: "999984", marker: "Server leaks inodes via ETags", slug: "etag-inode-leak"},

	// 999986 is NOT here. It reports a different header on each firing
	// and a single marker gave them all one identity — see
	// disclosedHeaders below.

	// 999996 carries at least two unrelated messages, which is why the
	// marker is load-bearing here rather than decorative. 2.1.5 and
	// 2.5.0 word them differently and 2.5.0 moved the listed-path
	// message to its own id, so both spellings are listed.
	{id: "999996", marker: "in robots.txt returned a non-forbidden", slug: "robots-listed-path"},
	{id: "999997", marker: "is returned a non-forbidden", slug: "robots-listed-path"},
	{id: "999996", marker: "which should be manually viewed", slug: "robots-entries"},

	// Added after installing Nikto 2.5.0 (task_74dc91dd). Every one of
	// these appeared on the FIRST real scan a working Nikto performed —
	// they were unreachable before, because 2.1.5 never got past the
	// server's error page. They arrived via the unclassified-item INFO
	// log, which is what that log is for.
	{id: "999970", marker: "Strict-Transport-Security HTTP header is not defined", slug: "missing-hsts"},
	{id: "999103", marker: "X-Content-Type-Options header is not set", slug: "missing-content-type-options"},
	{id: "999966", marker: "Content-Encoding header is set to", slug: "compression-enabled"},
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

// disclosedHeaderID is the item id nikto_headers.plugin uses for every
// "Retrieved <header> header: <value>" finding.
const disclosedHeaderID = "999986"

// disclosedHeaderMarker builds the anchored substring that identifies
// one header's message.
//
// Anchoring on BOTH sides is what makes the set unambiguous. Several
// entries below are substrings of others — server-name / x-server-name,
// x-ip / x-real-ip / x-clientip — and a bare header-name match would
// classify "Retrieved x-server-name header" as server-name depending on
// list order. With the "Retrieved " prefix and the " header" suffix, no
// entry's marker occurs inside another's; verified against the full
// list rather than assumed.
func disclosedHeaderMarker(header string) string {
	return "Retrieved " + header + " header"
}

// disclosedHeaders is the header list nikto_headers.plugin reports
// under id 999986 — its @interesting_headers qw// list
// (nikto_headers.plugin:468), transcribed verbatim and in its order.
//
// WHY EACH HEADER IS ITS OWN CLASS. This id previously had one curated
// entry, `{id: "999986", marker: "Retrieved ", slug: "disclosed-header"}`,
// and that reproduced the exact defect the 999100 work was meant to
// end. ComputeFingerprint hashes FindingType and TargetURL but NOT
// Description, and these findings are all reported against the same
// uri — the site root — so every disclosed header on a host collapsed
// into a single identity. Measured on a live scan: "Retrieved via
// header: 1.1 Caddy" and "Retrieved access-control-allow-origin header:
// *" both produced fingerprint 81ce4b48d135. Two distinct facts about
// the server, one row.
//
// That is the same shape as the four headers that shared one
// fingerprint under 999100, and it survived the fix for that because
// the marker here was generic enough to look like a class while
// behaving like a catch-all. The lesson is in the id-is-not-a-
// discriminator note at the top of this file, and the test to run
// before widening any FindingType is whether two findings that differ
// only in Description can share a TargetURL.
//
// The slug is "disclosed-header-<name>", so the class set stays
// enumerated HERE rather than being folded out of message text at
// runtime. That distinction is the point: the header names are ours,
// copied from Nikto's source, not taken from whatever a scanned server
// chose to send — a slug derived from server-supplied bytes would let a
// target mint unbounded finding types.
//
// A header Nikto ADDS to its list arrives as an unclassified item: raw
// nikto-999986 plus the INFO log, which is the visible signal to extend
// this list. Deliberately not a silent catch-all.
var disclosedHeaders = []string{
	"commerce-server-software", "daap-server", "dasl", "datacenter",
	"dav", "generator", "hosted-by", "hosted-with",
	"microsoftofficewebserver", "microsoftsharepointteamservices", "ms-author-via", "powered-by",
	"server-name", "serverid", "servlet-engine", "via",
	"x-aspnet-version", "x-blackboard-product", "x-cocoon-version", "x-compressed-by",
	"x-dmuser", "x-gallery-version", "x-hosted-at", "x-hostname",
	"x-isp", "x-powered-by", "x-responding-server", "x-served-by",
	"x-server", "x-server-name", "x-webserver", "x-owa-version",
	"access-control-allow-origin", "x-application-context", "cneonction", "nncoection",
	"xxx-real-ip", "bae-env-addr-sql-ip", "bae-env-addr-sql-port", "cf-connecting-ip",
	"fastly-client-ip", "incap-client-ip", "real-ip", "rlnclientipaddr",
	"true-client-ip", "x-clientip", "x-client-ip", "x-cluster-client-ip",
	"x-ip", "x-nokia-ipaddress", "x-real-ip", "x-wap-network-client-ip",
	"reason-code",
}

// classifyDisclosedHeader resolves a 999986 item to the specific header
// it reports. Returns false for any other id, and for a 999986 whose
// header is not in the list above.
func classifyDisclosedHeader(id, description string) (string, bool) {
	if id != disclosedHeaderID {
		return "", false
	}
	for _, h := range disclosedHeaders {
		if strings.Contains(description, disclosedHeaderMarker(h)) {
			return "disclosed-header-" + h, true
		}
	}
	return "", false
}

//go:generate go run gen_tuning.go -db $SHIELDSCAN_NIKTO_DB -version $SHIELDSCAN_NIKTO_VERSION -out tuning_table.go

// tuningClassSlug names Nikto's 16 test categories.
//
// This is the naming half of the db_tests classification; dbTestTuning
// (tuning_table.go, generated) is the facts half. Keeping them in
// separate files is the point: regenerating the table on a Nikto upgrade
// rewrites thousands of lines of data and touches none of the naming, so
// the diff a reviewer reads is "which tests changed category", not
// "which classes did we rename".
//
// The keys are Nikto's own tuning characters, documented in the header
// comment of databases/db_tests and matched by its -Tuning flag. The
// values are ours, and they are deliberately descriptive rather than
// severity-laden — see the severity note below.
//
// Nikto's own wording is kept where it is clear ("Interesting File /
// Seen in logs" → interesting-file) and tightened where it is not
// ("Remote File Retrieval - Inside Web Root" → file-retrieval-webroot).
// Counts are from the 2.5.0 database, for a sense of what a real scan
// can produce:
//
//	c 2342  1 1585  3 537  2 417  4 389  8 255  7 179  5 178
//	b 131   d 66    a 48   0 41   9 31   e 30   6 26    f 1
//
// SEVERITY IS NOT DERIVED FROM THIS, deliberately. Every Nikto finding
// is SeverityLow (Pattern 4 constant) and stays that way in this change.
// These categories are the first principled axis the engine has ever had
// for Nikto severity — sql-injection and command-execution plainly are
// not interesting-file — but acting on that changes what reaches the AI
// pipeline and what a customer is shown, so it is its own decision with
// its own evidence, not a rider on a classification change.
//
// Extending this map is REQUIRED if Nikto adds a category: the generator
// validates every tuning character against its legend and refuses to
// write a table containing one that is unnamed here.
var tuningClassSlug = map[byte]string{
	'0': "file-upload",
	'1': "interesting-file",
	'2': "misconfiguration",
	'3': "info-disclosure",
	'4': "injection",
	'5': "file-retrieval-webroot",
	'6': "dos",
	'7': "file-retrieval-serverwide",
	'8': "command-execution",
	'9': "sql-injection",
	'a': "auth-bypass",
	'b': "software-identification",
	'c': "remote-source-inclusion",
	'd': "webservice",
	'e': "admin-console",
	'f': "xml-injection",
}

// itemClass is the resolved identity of one Nikto item.
//
// slug empty means unresolved — neither a curated plugin class nor a
// known db_tests id — and the caller keeps the raw id and logs it.
type itemClass struct {
	slug   string
	drop   bool
	source string // "curated" or "db-test"; empty when unresolved
}

// resolveItem determines how a Nikto item is identified, consulting the
// two id families in order.
//
// The families are disjoint, which is what makes the ordering safe
// rather than merely conventional: Nikto reports ids from its PLUGINS
// (77 of them, mostly 999xxx but including 17 inside the db's numeric
// range) and ids from its TEST DATABASE (6951). Measured across Nikto
// 2.5.0, the two sets do not intersect. Note that they are therefore
// NOT separable by numeric range — "id < 007326 means db test" would be
// wrong for a third of the plugin ids — which is why membership in the
// generated table is the discriminator.
//
// Curated classes are consulted first anyway. They are message-anchored
// and hand-reviewed, so where one exists it is a better answer than a
// category, and putting them first means a future collision between the
// families resolves toward the specific rather than the general.
func resolveItem(id, description string) itemClass {
	if c, ok := classify(id, description); ok {
		return itemClass{slug: c.slug, drop: c.drop, source: "curated"}
	}
	if slug, ok := classifyDisclosedHeader(id, description); ok {
		return itemClass{slug: slug, source: "curated"}
	}
	if tuning, ok := dbTestTuning[id]; ok {
		if slug, named := tuningClassSlug[tuning]; named {
			return itemClass{slug: slug, source: "db-test"}
		}
	}
	return itemClass{}
}

// findingTypeFor returns the stable FindingType for an item.
//
// A resolved item gets its slug — curated for a plugin id, the test's
// category for a db_tests id. Anything else keeps "nikto-"+id:
// unchanged from the original behaviour, stable across scans, and
// logged so it surfaces.
//
// Deriving a slug from arbitrary message text was rejected, and the
// db_tests corpus now quantifies why. Comparing the database Nikto
// shipped in 2012 against the one it ships in 2026, of the 6253 ids
// present in both:
//
//	tuning identical   6198  (99.1%)
//	uri identical      6150  (98.4%)
//	message identical  2018  (32.3%)
//
// The category is the most durable thing Nikto knows about a test and
// the message is among the least, so a fingerprint keyed on wording
// would churn on every upgrade while one keyed on category holds.
//
// A COARSE CLASS DOES NOT COLLAPSE FINDINGS HERE, which is the thing to
// check before widening any FindingType. ComputeFingerprint hashes
// ToolName|FindingType|TargetURL|Parameter|CodeFile|CodeLine, and the
// 999100 disaster happened because four different headers were all
// observed on "/" — same TargetURL, so a shared FindingType collapsed
// them to one identity. db_tests findings are the opposite case: 6842
// distinct uris across 6951 tests, each becoming its own TargetURL, so
// nikto-interesting-file at /ftp/ and at /public/ are already distinct
// fingerprints. The residual is small and bounded: 31 uris map to more
// than one category and 35 (uri, category) pairs are shared by more
// than one test, all of them edge-case probe paths like "/", "//" and
// "/JUNK(10)".
func findingTypeFor(id, description string) string {
	if c := resolveItem(id, description); c.slug != "" {
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
