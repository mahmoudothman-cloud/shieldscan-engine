package nikto

import (
	"encoding/xml"
	"fmt"
	"os"
	"strings"

	"github.com/odyssey/shieldscan-engine/internal/events"
	"github.com/rs/zerolog"
)

// niktoScan is the top-level XML envelope (Nikto 2.x).
type niktoScan struct {
	XMLName     xml.Name           `xml:"niktoscan"`
	Version     string             `xml:"version,attr"`
	ScanDetails []niktoScanDetails `xml:"scandetails"`
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
// empty filename and die ("Unable to open ” for write"). NativeRunner
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

		for sdIdx, sd := range doc.ScanDetails {
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

				desc := strings.TrimSpace(it.Description)
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
