package zap

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/odyssey/shieldscan-engine/internal/events"
	"github.com/odyssey/shieldscan-engine/internal/tools/docker/service"
)

// zapAlert mirrors the alert object shape returned by
// /JSON/core/view/alerts/. Per Phase 0 V6 sample inspection: ALL
// numeric fields (cweid, wascid, pluginId, messageId, id) are JSON
// STRINGS. The reference field is a single string with newline
// separators (NOT an array). The tags field is map[string]string.
//
// Fields surfaced in V6 sample but NOT in this v1 struct (silently
// ignored by encoding/json) include sourceMessageId (int — the only
// integer in the response; semantically redundant with messageId
// string), other (alias of otherInfo per docs).
type zapAlert struct {
	ID          string            `json:"id"`
	PluginID    string            `json:"pluginId"`
	Name        string            `json:"name"`
	Risk        string            `json:"risk"`
	Confidence  string            `json:"confidence"`
	Description string            `json:"description"`
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Param       string            `json:"param"`
	Attack      string            `json:"attack"`
	Evidence    string            `json:"evidence"`
	CWEID       string            `json:"cweid"`
	WASCID      string            `json:"wascid"`
	Solution    string            `json:"solution"`
	Reference   string            `json:"reference"`
	MessageID   string            `json:"messageId"`
	SourceID    string            `json:"sourceid"`
	InputVector string            `json:"inputVector"`
	Other       string            `json:"other"`
	AlertRef    string            `json:"alertRef"`
	Tags        map[string]string `json:"tags"`
}

// fetchAlerts queries /JSON/core/view/alerts/ for the target's alert
// set. Per Q8 lock + Phase 0 V7: bulk fetch with start=0&count=5000;
// pagination upgrade forward-pinned if execution surfaces alert volume
// exceeding the cap.
func fetchAlerts(ctx context.Context, client *service.Client, targetURL string) ([]zapAlert, error) {
	path := fmt.Sprintf("/JSON/core/view/alerts/?baseurl=%s&start=0&count=5000",
		queryEscape(targetURL))
	body, err := client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("zap parser: fetch alerts: %w", err)
	}
	var resp struct {
		Alerts []zapAlert `json:"alerts"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("zap parser: parse alerts response: %w", err)
	}
	return resp.Alerts, nil
}

// queryEscape mirrors net/url.QueryEscape but is local to avoid
// importing net/url here (tiny fn; one of two call sites).
func queryEscape(s string) string {
	// Hand-roll for the common safe-character set; defer to
	// net/url.QueryEscape via strings.NewReplacer for the few
	// characters that matter for typical http(s) URLs.
	r := strings.NewReplacer(":", "%3A", "/", "%2F", "?", "%3F", "&", "%26", "=", "%3D", " ", "%20")
	return r.Replace(s)
}

// mapZAPRisk normalizes a ZAP risk string to the shieldscan-api
// Severity enum value. Per Phase 0 V8 finding: shieldscan-api enum =
// {"critical", "high", "medium", "low", "info"} (all lowercase).
// "False Positive" returns drop=true (V9 intersection — parser
// filters; cannot pass through to RawFinding.Severity per
// shieldscan-api Pydantic Literal strictness). Empty/unknown also
// drops defensively.
func mapZAPRisk(risk string) (severity string, drop bool) {
	switch risk {
	case "High":
		return "high", false
	case "Medium":
		return "medium", false
	case "Low":
		return "low", false
	case "Informational":
		return "info", false
	case "False Positive", "":
		return "", true
	default:
		return "", true
	}
}

// extractZAPTags pulls OWASP_* and CWE-* keys from the ZAP alert
// tags map and returns a sorted []string suitable for RawFinding.Tags.
// Per Phase 0 V12 finding: ZAP tags is map[string]string with
// structured keys (OWASP_2021_A05, CWE-693, POLICY_PENTEST, SYSTEMIC,
// etc.). Keep OWASP/CWE; drop POLICY_*/SYSTEMIC noise. Sort for
// deterministic ordering (stable hashes / fingerprints downstream).
func extractZAPTags(tags map[string]string) []string {
	if len(tags) == 0 {
		return nil
	}
	out := make([]string, 0, len(tags))
	for k := range tags {
		if strings.HasPrefix(k, "OWASP_") || strings.HasPrefix(k, "CWE-") {
			out = append(out, k)
		}
	}
	if len(out) == 0 {
		return nil
	}
	sort.Strings(out)
	return out
}

// parseAlerts converts ZAP alerts to RawFindings per Q8 mapping table
// (design doc §3.4) with Phase 0 drift-corrections applied:
//   - V6 cweid pass-through (already string in JSON; no strconv.Itoa)
//   - V8 Severity normalization via mapZAPRisk
//   - V9 False Positive drop
//   - V10 evidence into Metadata (not Request/Response typed fields)
//   - V11 solution into Metadata (not Description-append)
//   - V12 tags filtered to OWASP_*/CWE-* via extractZAPTags
//
// Identity fields (ToolName, EngineCategory, DiscoveredAt, Fingerprint)
// populated by service.DockerServiceRunner.Run enrichment loop per
// Task 7.5b service.go pattern.
func parseAlerts(alerts []zapAlert, scanTargetURL string) []events.RawFinding {
	out := make([]events.RawFinding, 0, len(alerts))
	for _, a := range alerts {
		severity, drop := mapZAPRisk(a.Risk)
		if drop {
			continue
		}
		f := events.RawFinding{
			Title:       a.Name,
			Severity:    severity,
			Description: a.Description,
			CWEID:       a.CWEID,
			TargetURL:   a.URL,
			Parameter:   a.Param,
			Payload:     a.Attack,
			References:  splitReferences(a.Reference),
			Tags:        extractZAPTags(a.Tags),
			Metadata:    buildAlertMetadata(a, scanTargetURL),
		}
		out = append(out, f)
	}
	return out
}

// splitReferences converts ZAP's newline-separated reference string
// into a []string suitable for RawFinding.References. Empty / single
// pure whitespace returns nil. Per Phase 0 V6 finding: ZAP reference
// is single string with "\n" separators, NOT array as documented.
func splitReferences(reference string) []string {
	if strings.TrimSpace(reference) == "" {
		return nil
	}
	parts := strings.Split(reference, "\n")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// buildAlertMetadata populates the per-tool structured payload per
// Q8 mapping table (snake_case keys; no tool-namespace prefix). The
// "target" key carries the scan-time target URL (cross-tool correlation
// per ADR-027 + Nmap precedent). Empty fields omitted to keep Metadata
// clean per Nmap consumer convention.
func buildAlertMetadata(a zapAlert, scanTargetURL string) map[string]string {
	m := map[string]string{
		"target":      scanTargetURL,
		"confidence":  a.Confidence,
		"plugin_id":   a.PluginID,
		"http_method": a.Method,
		"alert_ref":   a.AlertRef,
	}
	addIfNonEmpty(m, "wasc_id", a.WASCID)
	addIfNonEmpty(m, "evidence", a.Evidence)
	addIfNonEmpty(m, "attack_vector", a.Attack)
	addIfNonEmpty(m, "input_vector", a.InputVector)
	addIfNonEmpty(m, "other_info", a.Other)
	addIfNonEmpty(m, "solution", a.Solution)
	addIfNonEmpty(m, "zap_message_id", a.MessageID)
	addIfNonEmpty(m, "zap_source_id", a.SourceID)
	if rawTags := tagsRawJSON(a.Tags); rawTags != "" {
		m["tags_raw_json"] = rawTags
	}
	return m
}

func addIfNonEmpty(m map[string]string, k, v string) {
	if v != "" {
		m[k] = v
	}
}

// tagsRawJSON marshals the original ZAP tags map for Metadata audit/
// debug. Returns empty string if tags map is nil/empty (omit-when-empty
// per Nmap convention).
func tagsRawJSON(tags map[string]string) string {
	if len(tags) == 0 {
		return ""
	}
	b, err := json.Marshal(tags)
	if err != nil {
		return ""
	}
	return string(b)
}
