package events

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEvents_MaxFindingsPerEvent pins the ADR-017 soft cap at 1000.
// If a future change tries to bump this, the test failure surfaces
// the cap; the bumper is forced to read ADR-017's trigger conditions
// for Option-C migration before deciding whether to override.
func TestEvents_MaxFindingsPerEvent(t *testing.T) {
	assert.Equal(t, 1000, MaxFindingsPerEvent,
		"ADR-017 soft cap must equal 1000; bumping requires Option-C trigger evaluation")
}

// TestEvents_RecognizedEventTypes pins the EventType enum surface so
// downstream consumers (5.4 cancel subscriber, 5.5 processor, 5.6
// startup) reference stable constants.
func TestEvents_RecognizedEventTypes(t *testing.T) {
	progress := []EventType{
		EventJobStarted, EventReconStarted, EventSubdomainsDiscovered,
		EventLivenessProbed, EventReconCompleted, // M6.3 additions
		EventJobProgress, EventFindingDiscovered, EventJobCanceled, EventJobFailed,
	}
	completion := []EventType{EventJobCompleted, EventPartialFindings}
	cancel := []EventType{EventCancelRequested}

	for _, e := range progress {
		assert.NotEmpty(t, string(e), "progress event type must be non-empty")
	}
	for _, e := range completion {
		assert.NotEmpty(t, string(e), "completion event type must be non-empty")
	}
	for _, e := range cancel {
		assert.NotEmpty(t, string(e), "cancel event type must be non-empty")
	}

	// All event types must be unique strings.
	seen := map[EventType]bool{}
	for _, e := range append(append(progress, completion...), cancel...) {
		assert.False(t, seen[e], "event type %q duplicated", e)
		seen[e] = true
	}
}

// TestEvents_JobCompletedRoundTrip verifies that a JobCompletedEvent
// survives Marshal → Unmarshal without field loss. SPEC §7.3 schema
// fields preserved exactly; Findings/EventSeq populated.
func TestEvents_JobCompletedRoundTrip(t *testing.T) {
	original := JobCompletedEvent{
		EventType:      EventJobCompleted,
		JobID:          "job_a1b2c3d4",
		ScanID:         "scn_x1y2z3",
		Engine:         "nuclei",
		Status:         "completed",
		FindingCount:   2,
		DurationMs:     145000,
		IdempotencyKey: "scn_x1y2z3:nuclei:1711720200",
		Timestamp:      "2026-04-18T14:34:27Z",
		Findings: []RawFinding{
			{
				ToolName: "nuclei", EngineCategory: "dast",
				Title: "XSS in q parameter", Severity: "high",
				FindingType: "xss", CWEID: "CWE-79",
				TargetURL: "https://app.example.com/search",
				Parameter: "q", Payload: "<script>alert(1)</script>",
				Fingerprint: "abc123",
			},
			{
				ToolName: "nuclei", EngineCategory: "dast",
				Title: "Open redirect", Severity: "medium",
				FindingType: "open_redirect", CWEID: "CWE-601",
				TargetURL:   "https://app.example.com/redirect",
				Fingerprint: "def456",
			},
		},
		EventSeq: EventSeq{Index: 1, Total: 1},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	decoded, err := DecodeJobCompletedEvent(data)
	require.NoError(t, err)

	assert.Equal(t, original.JobID, decoded.JobID)
	assert.Equal(t, original.ScanID, decoded.ScanID)
	assert.Equal(t, original.Engine, decoded.Engine)
	assert.Equal(t, original.Status, decoded.Status)
	assert.Equal(t, original.FindingCount, decoded.FindingCount)
	assert.Equal(t, original.EventSeq, decoded.EventSeq)
	require.Len(t, decoded.Findings, 2)
	assert.Equal(t, "XSS in q parameter", decoded.Findings[0].Title)
	assert.Equal(t, "open_redirect", decoded.Findings[1].FindingType)
}

// TestEvents_DisallowUnknownFields pins the ADR-017 forcing-function
// transfer of M4 Pydantic extra="forbid" to the Go side. Unknown
// fields on the wire produce explicit decode errors rather than
// silent truncation.
//
// This catches schema-drift bugs at the wire boundary: if a future
// engineer adds a field to one side without updating the other, the
// consuming side errors out and surfaces the divergence immediately.
func TestEvents_DisallowUnknownFields(t *testing.T) {
	payload := []byte(`{
		"event_type": "job_completed",
		"job_id": "job_a1",
		"scan_id": "scn_x1",
		"engine": "nuclei",
		"status": "completed",
		"timestamp": "2026-04-18T14:34:27Z",
		"event_seq": {"index": 1, "total": 1},
		"future_field_not_in_schema": "surprise"
	}`)

	_, err := DecodeJobCompletedEvent(payload)
	require.Error(t, err, "unknown field should cause decode failure")
	assert.True(t,
		strings.Contains(err.Error(), "unknown field") ||
			strings.Contains(err.Error(), "future_field_not_in_schema"),
		"error should identify the offending field, got: %v", err)
}

// TestEvents_EventSeqValidation pins the ADR-017 sequencing
// invariants: Index >= 1, Total >= 1, Index <= Total. Plus the
// status/EventType cross-check: non-terminal events must use
// partial_findings status.
func TestEvents_EventSeqValidation(t *testing.T) {
	cases := []struct {
		name    string
		seq     EventSeq
		wantErr string
	}{
		{"valid single", EventSeq{Index: 1, Total: 1}, ""},
		{"valid sequenced first", EventSeq{Index: 1, Total: 3}, ""},
		{"valid sequenced terminal", EventSeq{Index: 3, Total: 3}, ""},
		{"index zero", EventSeq{Index: 0, Total: 1}, "index must be >= 1"},
		{"total zero", EventSeq{Index: 1, Total: 0}, "total must be >= 1"},
		{"index exceeds total", EventSeq{Index: 4, Total: 3}, "must not exceed"},
		{"both negative", EventSeq{Index: -1, Total: -1}, "index must be >= 1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.seq.Validate()
			if tc.wantErr == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
			}
		})
	}

	// Cross-check: non-terminal event must use partial_findings.
	nonTerminal := JobCompletedEvent{
		EventType: EventJobCompleted, // wrong: should be partial_findings
		JobID:     "j1", ScanID: "s1", Engine: "nuclei", Status: "running",
		Timestamp: "2026-04-18T14:34:27Z",
		EventSeq:  EventSeq{Index: 1, Total: 3},
	}
	err := nonTerminal.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "partial_findings")

	// Same payload with correct event_type passes:
	nonTerminal.EventType = EventPartialFindings
	require.NoError(t, nonTerminal.Validate())
}

// TestEvents_FindingsCapEnforced verifies that a payload exceeding
// MaxFindingsPerEvent fails Validate(). This is the structural test
// that pins the cap at the API surface; Task 5.5's emitter test will
// pin the splitting behavior.
func TestEvents_FindingsCapEnforced(t *testing.T) {
	tooMany := make([]RawFinding, MaxFindingsPerEvent+1)
	for i := range tooMany {
		tooMany[i] = RawFinding{
			ToolName: "nuclei", EngineCategory: "dast",
			Title: "f", Severity: "info", FindingType: "test",
		}
	}
	ev := JobCompletedEvent{
		EventType: EventJobCompleted,
		JobID:     "j1", ScanID: "s1", Engine: "nuclei", Status: "completed",
		Timestamp: "2026-04-18T14:34:27Z",
		Findings:  tooMany,
		EventSeq:  EventSeq{Index: 1, Total: 1},
	}
	err := ev.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds MaxFindingsPerEvent")
	assert.Contains(t, err.Error(), "ADR-017")
}

// TestEvents_CancelEventDecoding verifies the SPEC §7.4 cancel
// channel schema decodes correctly with DisallowUnknownFields.
func TestEvents_CancelEventDecoding(t *testing.T) {
	payload := []byte(`{
		"event_type": "cancel_requested",
		"scan_id": "scn_x1y2z3",
		"reason": "user_requested",
		"timestamp": "2026-04-18T14:33:00Z"
	}`)
	ev, err := DecodeCancelEvent(payload)
	require.NoError(t, err)
	assert.Equal(t, EventCancelRequested, ev.EventType)
	assert.Equal(t, "scn_x1y2z3", ev.ScanID)
	assert.Equal(t, "user_requested", ev.Reason)

	// Unknown field rejected:
	bad := []byte(`{"event_type":"cancel_requested","scan_id":"s","reason":"r","timestamp":"t","extra":"x"}`)
	_, err = DecodeCancelEvent(bad)
	require.Error(t, err)
}

// TestSplitForCompletion_SingleEvent pins the boundary cases that
// produce a single completion event: 0 findings, exactly 1000
// findings, and N≤1000 in between.
func TestSplitForCompletion_SingleEvent(t *testing.T) {
	base := JobCompletedEvent{
		EventType:    EventJobCompleted,
		JobID:        "j1",
		ScanID:       "s1",
		Engine:       "nuclei",
		Status:       "completed",
		FindingCount: 0, // populated below per case
		DurationMs:   1000,
		Timestamp:    "2026-04-18T14:34:27Z",
	}

	cases := []struct {
		name  string
		count int
	}{
		{"zero findings", 0},
		{"one finding", 1},
		{"exactly 1000 (boundary)", 1000},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := make([]RawFinding, tc.count)
			for i := range findings {
				findings[i] = RawFinding{ToolName: "nuclei", FindingType: "test"}
			}
			out := SplitForCompletion(findings, base)
			require.Len(t, out, 1, "≤1000 findings → single event")
			ev := out[0]
			assert.Equal(t, EventSeq{Index: 1, Total: 1}, ev.EventSeq)
			assert.Equal(t, EventJobCompleted, ev.EventType)
			assert.Equal(t, "completed", ev.Status)
			assert.Len(t, ev.Findings, tc.count)
			// Terminal event preserves base's authoritative fields.
			assert.Equal(t, 1000, ev.DurationMs)
		})
	}
}

// TestSplitForCompletion_MultiEventSequencing pins the sequencing
// cases that produce N>1 events: 1001 → 2 events, 2500 → 3 events.
func TestSplitForCompletion_MultiEventSequencing(t *testing.T) {
	base := JobCompletedEvent{
		EventType:    EventJobCompleted,
		JobID:        "j1",
		ScanID:       "s1",
		Engine:       "nuclei",
		Status:       "completed",
		FindingCount: 0, // splitter doesn't auto-populate; caller sets
		DurationMs:   145000,
		Timestamp:    "2026-04-18T14:34:27Z",
	}

	cases := []struct {
		name           string
		count          int
		expectedEvents int
		lastBatchSize  int
	}{
		{"1001 → 2 events (1000 + 1)", 1001, 2, 1},
		{"2500 → 3 events (1000 + 1000 + 500)", 2500, 3, 500},
		{"exactly 2000 → 2 events (1000 + 1000)", 2000, 2, 1000},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := make([]RawFinding, tc.count)
			for i := range findings {
				findings[i] = RawFinding{
					ToolName:    "nuclei",
					FindingType: "test",
				}
			}
			out := SplitForCompletion(findings, base)
			require.Len(t, out, tc.expectedEvents)

			// Total findings across batches must equal input count.
			total := 0
			for _, ev := range out {
				total += len(ev.Findings)
			}
			assert.Equal(t, tc.count, total, "no findings dropped or duplicated")

			// Terminal event size matches expected last batch.
			assert.Len(t, out[tc.expectedEvents-1].Findings, tc.lastBatchSize)

			// Each event has correct event_seq.
			for i, ev := range out {
				assert.Equal(t, EventSeq{Index: i + 1, Total: tc.expectedEvents}, ev.EventSeq,
					"event %d sequence", i)
			}
		})
	}
}

// TestSplitForCompletion_IntermediateStatusOverride pins ADR-017:
// intermediate events use EventType=EventPartialFindings + Status=
// "partial_findings"; terminal preserves base's EventType + Status.
func TestSplitForCompletion_IntermediateStatusOverride(t *testing.T) {
	base := JobCompletedEvent{
		EventType: EventJobCompleted,
		JobID:     "j1", ScanID: "s1", Engine: "nuclei",
		Status: "completed", DurationMs: 5000,
		Timestamp: "2026-04-18T14:34:27Z",
	}
	findings := make([]RawFinding, 2500)
	for i := range findings {
		findings[i] = RawFinding{ToolName: "nuclei", FindingType: "test"}
	}
	out := SplitForCompletion(findings, base)
	require.Len(t, out, 3)

	// Intermediate batches: index 0, 1.
	for i := 0; i < 2; i++ {
		assert.Equal(t, EventPartialFindings, out[i].EventType, "intermediate event %d type", i)
		assert.Equal(t, "partial_findings", out[i].Status, "intermediate event %d status", i)
		assert.False(t, out[i].EventSeq.IsTerminal(), "intermediate event %d not terminal", i)
	}

	// Terminal batch: index 2.
	assert.Equal(t, EventJobCompleted, out[2].EventType)
	assert.Equal(t, "completed", out[2].Status)
	assert.True(t, out[2].EventSeq.IsTerminal())
}

// TestSplitForCompletion_TerminalCarriesAuthoritative pins ADR-017:
// FindingCount + DurationMs are zeroed on intermediate events,
// preserved on terminal.
func TestSplitForCompletion_TerminalCarriesAuthoritative(t *testing.T) {
	base := JobCompletedEvent{
		EventType: EventJobCompleted,
		JobID:     "j1", ScanID: "s1", Engine: "nuclei",
		Status: "completed",
		// Caller sets FindingCount to total across batches:
		FindingCount: 2500,
		DurationMs:   145000,
		Timestamp:    "2026-04-18T14:34:27Z",
	}
	findings := make([]RawFinding, 2500)
	for i := range findings {
		findings[i] = RawFinding{ToolName: "nuclei", FindingType: "test"}
	}
	out := SplitForCompletion(findings, base)
	require.Len(t, out, 3)

	// Intermediate: zeroed.
	assert.Zero(t, out[0].FindingCount, "intermediate finding_count")
	assert.Zero(t, out[0].DurationMs, "intermediate duration_ms")
	assert.Zero(t, out[1].FindingCount)
	assert.Zero(t, out[1].DurationMs)

	// Terminal: authoritative.
	assert.Equal(t, 2500, out[2].FindingCount)
	assert.Equal(t, 145000, out[2].DurationMs)
}

// TestDecodeJobDispatch_PythonFixture is the cross-repo wire-format
// pin: deserialize the canonical Python ScanQueue.dispatch fixture
// and verify every documented field decodes correctly.
//
// If this test fails, one of:
//   - Python emit shape drifted (rare; M4 is shipped + tested)
//   - Go struct tags wrong (most likely on first failure)
//   - Python added a new field not yet in JobDispatch struct
//     (DisallowUnknownFields surfaces this immediately)
func TestDecodeJobDispatch_PythonFixture(t *testing.T) {
	job, err := DecodeJobDispatch(FixtureJobDispatchPythonV1)
	require.NoError(t, err)

	assert.Equal(t, "job_a1b2c3d4", job.ID)
	assert.Equal(t, "scn_x1y2z3", job.ScanID)
	assert.Equal(t, "org_m1n2o3", job.OrganizationID)
	assert.Equal(t, "nuclei", job.Engine)
	assert.Equal(t, "scn_x1y2z3:nuclei:1711720200", job.IdempotencyKey)
	assert.Equal(t, "https://app.example.com", job.Target.URL)
	assert.Equal(t, "web", job.Target.TargetType)
	assert.True(t, job.Target.DomainVerified)
	require.NotNil(t, job.Auth)
	assert.Equal(t, "cookie", job.Auth.Type)
	assert.Equal(t, "session=abc123; csrf=xyz789", job.Auth.Data)
	assert.Equal(t, "standard", job.Config["depth"])
	assert.Nil(t, job.MobileConfig)
	assert.Equal(t, "shieldscan:progress:scn_x1y2z3", job.CallbackChannel)
	assert.Equal(t, "2026-04-18T14:30:00Z", job.CreatedAt)
}

// TestDecodeJobDispatch_DisallowUnknownFields pins the contract
// strictness: a fixture with an extra top-level field rejected.
func TestDecodeJobDispatch_DisallowUnknownFields(t *testing.T) {
	bad := []byte(`{"id":"j","scan_id":"s","organization_id":"o","engine":"n",
		"idempotency_key":"k","target":{"url":"u","target_type":"web","domain_verified":true},
		"auth":null,"config":{},"mobile_config":null,
		"callback_channel":"c","created_at":"t",
		"future_field_python_added":"surprise"}`)
	_, err := DecodeJobDispatch(bad)
	require.Error(t, err)
	assert.Contains(t, strings.ToLower(err.Error()), "unknown field")
}

// TestDecodeJobCompletedEvent_PythonFixture is the reverse-direction
// cross-repo pin: deserialize the fixture matching what Go-side
// CompletionsPublisher emits, asserting Python's expected shape.
func TestDecodeJobCompletedEvent_PythonFixture(t *testing.T) {
	ev, err := DecodeJobCompletedEvent(FixtureJobCompletedPythonV1)
	require.NoError(t, err)
	assert.Equal(t, EventJobCompleted, ev.EventType)
	assert.Equal(t, "job_a1b2c3d4", ev.JobID)
	assert.Equal(t, "scn_x1y2z3", ev.ScanID)
	assert.Equal(t, "completed", ev.Status)
	assert.Equal(t, 2, ev.FindingCount)
	assert.Equal(t, 145000, ev.DurationMs)
	assert.Equal(t, EventSeq{Index: 1, Total: 1}, ev.EventSeq)
	require.Len(t, ev.Findings, 2)
	assert.Equal(t, "XSS in q parameter", ev.Findings[0].Title)
	assert.Equal(t, "open_redirect", ev.Findings[1].FindingType)

	// Re-marshal and verify round-trip preserves shape (subset check
	// — full byte-equivalence is fragile due to map key ordering).
	data, err := json.Marshal(ev)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"event_type":"job_completed"`)
	assert.Contains(t, string(data), `"event_seq":{"index":1,"total":1}`)

	// SPEC §7.3 schema extension (M6-close-followup, ADR-024):
	// finding[0] in the canonical fixture populates all 4 new fields.
	assert.Equal(t, []string{
		"https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
		"https://example.com/advisory/2024-001",
	}, ev.Findings[0].References)
	assert.Equal(t, []string{"xss", "owasp-top-10"}, ev.Findings[0].Tags)
	assert.Equal(t, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", ev.Findings[0].CVSSVector)
	assert.Equal(t, []string{"CWE-20", "CWE-78"}, ev.Findings[0].AdditionalCWEs)

	// finding[1] leaves the new fields unset; backward-compat regression
	// guard (omitempty discipline holds on both encode + decode paths).
	assert.Nil(t, ev.Findings[1].References)
	assert.Nil(t, ev.Findings[1].Tags)
	assert.Empty(t, ev.Findings[1].CVSSVector)
	assert.Nil(t, ev.Findings[1].AdditionalCWEs)
}

// TestRawFinding_NewFieldsRoundtrip verifies the 4 ADR-024 fields
// survive a full marshal → unmarshal cycle without truncation or
// reordering. Pins the wire-format symmetry SPEC §7.3 + ADR-024
// rely on.
func TestRawFinding_NewFieldsRoundtrip(t *testing.T) {
	original := RawFinding{
		ToolName:       "nuclei",
		EngineCategory: "dast",
		Title:          "XSS",
		Severity:       "high",
		FindingType:    "xss",
		References: []string{
			"https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
			"https://example.com/advisory/2024-001",
		},
		Tags:           []string{"xss", "owasp-top-10"},
		CVSSVector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		AdditionalCWEs: []string{"CWE-20", "CWE-78"},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded RawFinding
	require.NoError(t, json.Unmarshal(data, &decoded))

	assert.Equal(t, original.References, decoded.References)
	assert.Equal(t, original.Tags, decoded.Tags)
	assert.Equal(t, original.CVSSVector, decoded.CVSSVector)
	assert.Equal(t, original.AdditionalCWEs, decoded.AdditionalCWEs)
}

// TestRawFinding_NewFieldsOmitemptyWhenAbsent verifies the 4 new
// fields disappear from JSON when unset. Backward-compat regression
// guard: existing engine emissions without these fields produce
// identical wire bytes to the pre-§7.3 era (no spurious empty
// `"references":null` etc.).
func TestRawFinding_NewFieldsOmitemptyWhenAbsent(t *testing.T) {
	finding := RawFinding{
		ToolName:       "gitleaks",
		EngineCategory: "secrets",
		Title:          "Hardcoded credential",
		Severity:       "critical",
		FindingType:    "secret",
		// New fields deliberately not set.
	}

	data, err := json.Marshal(finding)
	require.NoError(t, err)

	jsonStr := string(data)
	for _, field := range []string{"references", "tags", "cvss_vector", "additional_cwes"} {
		assert.NotContains(t, jsonStr, field,
			"omitempty must drop %q when unset; got JSON: %s", field, jsonStr)
	}
}
