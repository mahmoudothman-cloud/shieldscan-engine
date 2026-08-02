package sslyze

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/odyssey/shieldscan-engine/internal/events"
	"github.com/odyssey/shieldscan-engine/internal/tools/jsonx"
	"github.com/rs/zerolog"
)

// parseOutput returns a closure that parses SSLyze --json_out
// payloads into RawFindings. Returned closure satisfies
// NativeRunner.ParseOutput.
//
// Format asymmetries vs prior M6 parsers (DRIFT-LOG M6.4 entry 4):
//   - 6.1 Nuclei: JSONL (newline-separated single-line objects).
//   - 6.2 Semgrep: single-doc JSON with results[] array.
//   - 6.5 Gitleaks: bare JSON array of finding objects.
//   - 6.4 SSLyze: single-doc JSON with structured plugin diagnostics
//     (NOT a finding list). Parser SYNTHESIZES findings via per-
//     plugin domain rules (rules.go).
//
// Algorithm:
//
//  1. Empty stdout → ([], nil).
//  2. json.Unmarshal into map[string]any. Top-level malformed JSON
//     is FATAL (cannot recover partial data from broken structure).
//  3. Extract server_scan_results[]. Missing or wrong-type → empty
//     happy path (matches sslyze_empty.json fixture).
//  4. For each server result:
//     a. Type-assert; skip + WARN if not an object.
//     b. Check scan_status. Anything other than "COMPLETED" is per-
//     server skip with WARN (per H.4: drop silently, NOT emit info
//     finding).
//     c. Derive target_hostport from server_location.
//     d. Iterate scan_result entries. For each (pluginKey, entry),
//     dispatch via pluginRules table. Plugins not in the table are
//     silently ignored (forward-compat).
//  5. Return aggregated findings.
//
// ParseOutput leaves these RawFinding fields EMPTY (NativeRunner.Run
// enriches them after parsing per the ToolRunner contract):
//   - ToolName ("sslyze")
//   - EngineCategory ("ssl")
//   - DiscoveredAt (RFC3339)
//   - Fingerprint (via tools.ComputeFingerprint)
func parseOutput(log zerolog.Logger) func([]byte) ([]events.RawFinding, error) {
	return func(stdout []byte) ([]events.RawFinding, error) {
		findings := []events.RawFinding{}
		if len(stdout) == 0 {
			return findings, nil
		}

		// UseNumber so JSON numbers decode as json.Number (string-backed)
		// rather than float64. SSLyze embeds the server's RSA public-key
		// modulus as a JSON integer (600+ digits for a 2048-bit key); the
		// default float64 decode overflows on it ("cannot unmarshal number
		// ... into Go value of type float64") and fails the WHOLE parse,
		// even though the parser never reads the modulus. json.Number holds
		// it losslessly; the small numbers the parser does read (e.g. port)
		// resolve via jsonx.ExtractFloat, which handles json.Number.
		dec := json.NewDecoder(bytes.NewReader(stdout))
		dec.UseNumber()
		var doc map[string]any
		if err := dec.Decode(&doc); err != nil {
			return nil, fmt.Errorf("sslyze: parse JSON: %w", err)
		}

		serverResults, ok := doc["server_scan_results"].([]any)
		if !ok {
			// Missing or wrong-type → empty happy path.
			return findings, nil
		}

		for i, srvAny := range serverResults {
			srv, ok := srvAny.(map[string]any)
			if !ok {
				log.Warn().Int("index", i).
					Msg("sslyze: server_scan_results entry not an object; dropping")
				continue
			}

			status := jsonx.ExtractString(srv, "scan_status")
			if status != "COMPLETED" {
				// Per H.4: drop with WARN; don't emit info finding.
				log.Warn().
					Int("index", i).
					Str("scan_status", status).
					Str("hostname", jsonx.ExtractString(jsonx.ExtractMap(srv, "server_location"), "hostname")).
					Msg("sslyze: per-server scan failed; dropping (drop-with-warn per H.4)")
				continue
			}

			target := deriveTargetHostport(srv)
			scanResult := jsonx.ExtractMap(srv, "scan_result")
			if scanResult == nil {
				log.Warn().Int("index", i).
					Msg("sslyze: scan_result missing on COMPLETED entry; dropping")
				continue
			}

			for pluginKey, pluginAny := range scanResult {
				plugin, ok := pluginAny.(map[string]any)
				if !ok {
					continue
				}
				rule, registered := pluginRules[pluginKey]
				if !registered {
					// Forward-compat: unknown plugins silently ignored.
					continue
				}
				findings = append(findings, rule(plugin, target)...)
			}
		}

		return findings, nil
	}
}

// deriveTargetHostport returns "<hostname>:<port>" from
// server_location, or "" if hostname missing. Used as TargetURL on
// every synthesized finding for the server.
func deriveTargetHostport(srv map[string]any) string {
	loc := jsonx.ExtractMap(srv, "server_location")
	hostname := jsonx.ExtractString(loc, "hostname")
	if hostname == "" {
		return ""
	}
	port := int(jsonx.ExtractFloat(loc, "port"))
	if port == 0 {
		return hostname
	}
	return fmt.Sprintf("%s:%d", hostname, port)
}
