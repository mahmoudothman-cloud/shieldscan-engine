package corstest

import (
	"bufio"
	"bytes"
	"strings"

	"github.com/odyssey/shieldscan-engine/internal/events"
	"github.com/rs/zerolog"
)

// statusVulnerablePrefix marks lines indicating a vulnerable host.
// CORStest outputs lines like "<host> - Vulnerable: <description>".
// Hosts with "Not vulnerable" status are filtered out (no finding).
const (
	statusVulnerable    = "Vulnerable"
	statusNotVulnerable = "Not vulnerable"
)

// pendingRecord accumulates fields from a multi-line per-host record
// before the status line emits a finding.
type pendingRecord struct {
	resource string
	origin   string
	acao     string
	acac     string
}

func (p *pendingRecord) reset() {
	p.resource = ""
	p.origin = ""
	p.acao = ""
	p.acac = ""
}

func (p *pendingRecord) hasFields() bool {
	return p.resource != "" || p.origin != "" || p.acao != "" || p.acac != ""
}

// parseOutput returns a closure satisfying NativeRunner.ParseOutput.
//
// CORStest output (verbose mode -v) is human-readable text with ANSI
// color codes. Per-host record:
//
//	------------------------------------------------------------------------
//	Resource: <URL>
//	Origin:   <URL>
//	ACAO:     <header value>
//	ACAC:     <header value>
//	<ANSI>{host} - {status}: {description}<ANSI-reset>
//
// Algorithm: bufio.Scanner; ANSI-strip each line; multi-line state
// machine accumulates fields until the status line emits a finding.
// Hosts marked "Not vulnerable" are filtered out (no finding emitted).
//
// Parser-resilience: orphan status lines (no preceding record fields)
// are dropped with WARN; records without status lines (interrupted
// mid-record) are dropped silently when the next separator arrives.
//
// FIRST text-with-ANSI parser shape in M6 (DRIFT-LOG M6.6 entry 8;
// 5th format after JSONL + single-doc JSON + JSON-array + XML).
//
// ParseOutput leaves these RawFinding fields EMPTY (NativeRunner
// enriches after parsing):
//   - ToolName ("corstest"), EngineCategory ("api")
//   - DiscoveredAt (RFC3339)
//   - Fingerprint (via tools.ComputeFingerprint)
func parseOutput(log zerolog.Logger) func([]byte) ([]events.RawFinding, error) {
	return func(stdout []byte) ([]events.RawFinding, error) {
		findings := []events.RawFinding{}
		if len(stdout) == 0 {
			return findings, nil
		}

		scanner := bufio.NewScanner(bytes.NewReader(stdout))
		// CORStest lines are short (<1 KiB typically); default 64 KiB
		// buffer is plenty.
		var pending pendingRecord
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			raw := scanner.Text()
			line := strings.TrimSpace(stripANSI(raw))
			if line == "" {
				continue
			}

			// Separator → reset pending record.
			if strings.HasPrefix(line, "------") {
				pending.reset()
				continue
			}

			// Field lines.
			if strings.HasPrefix(line, "Resource:") {
				pending.resource = strings.TrimSpace(strings.TrimPrefix(line, "Resource:"))
				continue
			}
			if strings.HasPrefix(line, "Origin:") {
				pending.origin = strings.TrimSpace(strings.TrimPrefix(line, "Origin:"))
				continue
			}
			if strings.HasPrefix(line, "ACAO:") {
				pending.acao = strings.TrimSpace(strings.TrimPrefix(line, "ACAO:"))
				continue
			}
			if strings.HasPrefix(line, "ACAC:") {
				pending.acac = strings.TrimSpace(strings.TrimPrefix(line, "ACAC:"))
				continue
			}

			// Status line: "<host> - <status>: <description>".
			// Detect by " - " separator + status keywords.
			if host, status, desc, ok := parseStatusLine(line); ok {
				if status == statusNotVulnerable {
					// Filtered; no finding emitted. Reset for next record.
					pending.reset()
					continue
				}
				if !pending.hasFields() {
					log.Warn().
						Int("line_num", lineNum).
						Str("host", host).
						Msg("corstest: orphan status line (no preceding record); dropping")
					continue
				}
				findings = append(findings, recordToFinding(host, status, desc, &pending))
				pending.reset()
				continue
			}

			// Other lines (e.g., Python prints from script). Ignored.
		}

		if err := scanner.Err(); err != nil {
			return findings, nil // best-effort; return what we parsed
		}
		return findings, nil
	}
}

// parseStatusLine extracts (host, status, description) from a
// CORStest status line of the form "<host> - <status>: <description>".
// Returns (zero, zero, zero, false) on no match.
//
// Status must be "Vulnerable" or "Not vulnerable" prefix; description
// is everything after the first colon.
func parseStatusLine(line string) (host, status, desc string, ok bool) {
	dashIdx := strings.Index(line, " - ")
	if dashIdx < 0 {
		return "", "", "", false
	}
	host = strings.TrimSpace(line[:dashIdx])
	rest := strings.TrimSpace(line[dashIdx+3:])

	// rest is "<status>: <description>"
	colonIdx := strings.Index(rest, ":")
	if colonIdx < 0 {
		return "", "", "", false
	}
	status = strings.TrimSpace(rest[:colonIdx])
	desc = strings.TrimSpace(rest[colonIdx+1:])

	// Validate status keyword to avoid false-positives on random " - "
	// containing lines.
	if !strings.HasPrefix(status, statusVulnerable) && status != statusNotVulnerable {
		return "", "", "", false
	}
	return host, status, desc, true
}

// recordToFinding builds a RawFinding from the accumulated pending
// fields + the status line components.
//
// Reductions (DRIFT-LOG M6.6 entry 12):
//   - Resource + Origin → folded into Description
//   - ACAO + ACAC → folded into Description
func recordToFinding(host, status, desc string, p *pendingRecord) events.RawFinding {
	// Description folds Resource+Origin+ACAO+ACAC for context.
	var b strings.Builder
	b.WriteString(desc)
	if p.resource != "" {
		b.WriteString(" (resource: ")
		b.WriteString(p.resource)
		b.WriteString(")")
	}
	if p.origin != "" && p.origin != "-" {
		b.WriteString(" (origin: ")
		b.WriteString(p.origin)
		b.WriteString(")")
	}
	if p.acao != "" && p.acao != "-" {
		b.WriteString(" (ACAO: ")
		b.WriteString(p.acao)
		b.WriteString(")")
	}
	if p.acac != "" && p.acac != "-" {
		b.WriteString(" (ACAC: ")
		b.WriteString(p.acac)
		b.WriteString(")")
	}

	targetURL := p.resource
	if targetURL == "" {
		targetURL = host
	}

	return events.RawFinding{
		Title:       host + " - " + status,
		Description: b.String(),
		Severity:    SeverityMedium,
		FindingType: "corstest-cors-misconfig",
		CWEID:       CWEPermissiveCrossDomain,
		TargetURL:   targetURL,
	}
}
