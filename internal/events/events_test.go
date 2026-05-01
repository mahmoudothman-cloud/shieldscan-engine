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
