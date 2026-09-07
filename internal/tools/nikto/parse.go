package nikto

import (
	"encoding/xml"
	"fmt"
	"os"
	"strings"

	"github.com/odyssey/shieldscan-engine/internal/events"
	"github.com/rs/zerolog"
)

// niktoScan is the XML envelope, and it is deliberately root-agnostic.
//
// Nikto changed its root element between versions, which a fixture
// written by hand could never have revealed:
//
//	2.1.5   <niktoscan> ... <scandetails>
//	2.5.0+  <niktoscans> <niktoscan> ... <scandetails>
//
// Omitting XMLName lets Unmarshal accept either root. `Nested` then
// picks up the inner <niktoscan> elements the plural form introduces;
// `ScanDetails` picks up the direct children the singular form has.
// scanDetails() flattens the two.
//
// Pinning XMLName to "niktoscan" cost a hard parse failure —
// `expected element type <niktoscan> but have <niktoscans>` — on every
// scan the moment a working Nikto was installed.
type niktoScan struct {
	Version     string             `xml:"version,attr"`
	ScanDetails []niktoScanDetails `xml:"scandetails"`
	Nested      []niktoScan        `xml:"niktoscan"`
}

// scanDetails flattens the envelope into the per-host sections,
// whichever nesting the emitting Nikto used.
func (n niktoScan) scanDetails() []niktoScanDetails {
	out := append([]niktoScanDetails(nil), n.ScanDetails...)
	for _, inner := range n.Nested {
		out = append(out, inner.scanDetails()...)
	}
	return out
}

// niktoScanDetails is the per-server scan section. Multi-host scans
// produce multiple entries; M6.6 invokes per-target so typically one.
type niktoScanDetails struct {
	TargetIP   string      `xml:"targetip,attr,omitempty"`
	TargetHost string      `xml:"targethostname,attr,omitempty"`
	TargetPort string      `xml:"targetport,attr,omitempty"`
	SiteName   string      `xml:"sitename,attr,omitempty"`
	Items      []niktoItem `xml:"item"`
}

// niktoItem is a single Nikto finding from the XML output.
//
// Fields explicitly DROPPED at M6.6 (Pattern 4 reductions, DRIFT M6.6
// entry 12):
//   - osvdbid, osvdblink (OSVDB defunct since 2016; references stale)
//   - namelink, iplink (redundant with uri + scan target)
type niktoItem struct {
	ID          string `xml:"id,attr"`
	Method      string `xml:"method,attr,omitempty"`
	Description string `xml:"description"` // CDATA-wrapped
	URI         string `xml:"uri"`
}

// parseOutputFile returns a closure satisfying NativeRunner.ParseOutputFile
// (ADR-023 OutputFile mode).
//
// Nikto 2.1.5+ XML format. Stable across 2.x. File-output mode: Nikto's
// XML report plugin (nikto_report_xml.plugin) writes to the -o path and
// does NOT stream to stdout — `-Format xml` without `-o` makes it open an
// empty filename and die with an "Unable to open ... for write" error
// naming an empty path. NativeRunner
// mints the tempfile, substitutes it for the -o placeholder, and hands
// this closure the populated path.
//
// Per-item field map (Nikto → RawFinding):
//
//	item.id + item.description → FindingType (see classify.go)
//	item.description           → Title (human-readable, capped)
//	item.description           → Description (verbatim)
//	item.uri (combined with scandetails.sitename)
//	                           → TargetURL
//	(constant)                 → Severity = SeverityLow (Pattern 4)
//	(constant)                 → CWEID = "" (Nikto findings span too
//	                             many CWE classes for a meaningful
//	                             constant)
//
// Required fields gate: id + description non-empty. Missing either
// → skip with WARN.
//
// Non-findings are dropped here (classify.go): Nikto's "Uncommon header"
// class reports headers the site correctly sets, and reporting them cost
// a live scan 9 of its 41 vulnerabilities plus an AI-written remediation
// for each. Dropping at the parser rather than downstream keeps the
// engine's output meaning "things that are wrong", which is what every
// consumer already assumes it means.
//
// ParseOutput leaves these RawFinding fields EMPTY (NativeRunner.Run
// enriches after parsing):
//   - ToolName ("nikto"), EngineCategory ("infrastructure")
//   - DiscoveredAt (RFC3339)
//   - Fingerprint (via tools.ComputeFingerprint)
func parseOutputFile(log zerolog.Logger) func(string) ([]events.RawFinding, error) {
	return func(outputFilePath string) ([]events.RawFinding, error) {
		findings := []events.RawFinding{}
		data, err := os.ReadFile(outputFilePath) //nolint:gosec // G304: NativeRunner-minted tempfile
		if err != nil {
			return nil, fmt.Errorf("nikto: read output file: %w", err)
		}
		if len(data) == 0 {
			return findings, nil
		}

		var doc niktoScan
		if err := xml.Unmarshal(data, &doc); err != nil {
			return nil, fmt.Errorf("nikto: parse XML: %w", err)
		}

		for sdIdx, sd := range doc.scanDetails() {
			for itemIdx, it := range sd.Items {
				// Required-fields gate.
				if it.ID == "" || it.Description == "" {
					log.Warn().
						Int("scandetails_index", sdIdx).
						Int("item_index", itemIdx).
						Str("item_id", it.ID).
						Msg("nikto: item missing id or description; dropping")
					continue
				}

				desc := trimRootPathPrefix(strings.TrimSpace(it.Description))
				class, known := classify(it.ID, desc)
				if known && class.drop {
					log.Debug().
						Str("item_id", it.ID).
						Str("class", class.slug).
						Msg("nikto: observation, not a finding; dropping")
					continue
				}
				if !known {
					// A class we have not characterised. It still becomes a
					// finding under nikto-<id>; the log is what stops a new
					// message shape from joining a catch-all unnoticed.
					log.Info().
						Str("item_id", it.ID).
						Str("description", desc).
						Msg("nikto: unclassified item; using the raw id as finding_type")
				}
				findings = append(findings, itemToFinding(it, sd, desc))
			}
		}
		return findings, nil
	}
}

// itemToFinding builds a RawFinding from a single Nikto <item> +
// its parent <scandetails> context.
//
// desc is the already-trimmed description; the caller has it because it
// needed it to classify the item.
func itemToFinding(it niktoItem, sd niktoScanDetails, desc string) events.RawFinding {
	// Combine sitename + uri → TargetURL. Nikto's sitename is like
	// "http://example.com:443"; uri is the path like "/admin/".
	//
	// Note the scheme: Nikto 2.1.5 writes "http://" even for a target on
	// 443, because it never established TLS. That is a symptom, not a
	// formatting quirk — see the preflight in nikto.go.
	targetURL := combineSiteURI(sd.SiteName, it.URI)

	return events.RawFinding{
		Title:       titleFor(desc),
		Description: desc,
		Severity:    SeverityLow, // Pattern 4 constant
		FindingType: findingTypeFor(it.ID, desc),
		TargetURL:   targetURL,
	}
}

// rootPathPrefixes are the description prefixes Nikto 2.5.0+ adds that
// carry no information. Both spell "the site itself"; Nikto uses "." for
// checks it runs against the server rather than a path.
var rootPathPrefixes = []string{"/: ", ".: "}

// trimRootPathPrefix removes the leading "/: " Nikto 2.5.0+ prepends to
// descriptions for findings on the site root.
//
//	2.1.5   The anti-clickjacking X-Frame-Options header is not present.
//	2.5.0   /: The anti-clickjacking X-Frame-Options header is not present.
//
// Only the site-root prefixes are stripped, and deliberately so. A prefix naming
// a real path is context the title should keep — "/robots.txt: Entry
// '/ftp/' is returned a non-forbidden..." reads correctly, whereas
// stripping it by matching the item's own uri leaves "contains 1 entry
// which should be manually viewed", a sentence with no subject. "/" is
// the only prefix that adds nothing TargetURL does not already say.
func trimRootPathPrefix(desc string) string {
	for _, p := range rootPathPrefixes {
		if trimmed, ok := strings.CutPrefix(desc, p); ok {
			return trimmed
		}
	}
	return desc
}

// combineSiteURI merges sitename ("https://host:port") with a uri
// path ("/admin/") into a canonical URL. Defensive against either
// being empty.
func combineSiteURI(siteName, uri string) string {
	if siteName == "" {
		return uri
	}
	if uri == "" {
		return siteName
	}
	// Avoid double-slash if siteName ends with "/" and uri starts with "/".
	site := strings.TrimSuffix(siteName, "/")
	if !strings.HasPrefix(uri, "/") {
		return site + "/" + uri
	}
	return site + uri
}
