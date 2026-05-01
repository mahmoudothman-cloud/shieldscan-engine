// Package events owns the SPECIFICATION §7 inter-service wire
// schemas and the constants governing event sequencing.
//
// All Go-side producers (worker progress publisher, completions
// publisher) and Go-side consumers (cancel subscriber, M5+ batch
// processors) reference the struct types and constants defined here.
// This is the single source of truth for the Redis-mediated contract
// with the Python API; deviations break the M4 Python consumers
// (CompletionsConsumer, ProgressSubscriber) and the SSE clients.
//
// JSON encoding uses DisallowUnknownFields throughout (transferred
// from the M4 Pydantic extra="forbid" discipline). Unknown fields on
// the wire produce explicit errors rather than silent truncation.
package events

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// EventType enumerates the event_type values that may appear on the
// shieldscan:* Redis primitives. Producers MUST use these constants;
// consumers MUST validate against them.
type EventType string

const (
	// Progress stream (shieldscan:progress:{scan_id})
	EventJobStarted           EventType = "job_started"
	EventReconStarted         EventType = "recon_started"
	EventSubdomainsDiscovered EventType = "subdomains_discovered"
	EventJobProgress          EventType = "job_progress"
	EventFindingDiscovered    EventType = "finding_discovered"
	EventJobCanceled          EventType = "job_canceled"
	EventJobFailed            EventType = "job_failed"

	// Completions channel (shieldscan:completions)
	EventJobCompleted    EventType = "job_completed"
	EventPartialFindings EventType = "partial_findings" // ADR-017 sequenced batches
	EventCancelRequested EventType = "cancel_requested" // shieldscan:cancel:{scan_id}
)

// MaxFindingsPerEvent is the ADR-017 soft cap on findings carried
// inline in a single job_completed event. Workers exceeding this cap
// MUST split into multiple events with EventSeq populated.
//
// Trigger conditions for promoting findings persistence to R2 staging
// (Option C migration) are documented in ADR-017. If you're tempted
// to bump this constant, read the trigger conditions first — the cap
// is a forcing function, not a tuning knob.
const MaxFindingsPerEvent = 1000

// EventSeq describes the position of a sequenced job_completed event
// within a multi-event batch. For single-event completions (≤1000
// findings), Index = Total = 1. For batches, Index ranges 1..Total
// inclusive; the terminal event has Index == Total.
//
// Per ADR-017, EventSeq is REQUIRED on every job_completed event for
// forward-compatibility — consumers always read it rather than
// branching on presence.
type EventSeq struct {
	Index int `json:"index"`
	Total int `json:"total"`
}

// Validate enforces the EventSeq invariants:
//   - Index >= 1
//   - Total >= 1
//   - Index <= Total
func (s EventSeq) Validate() error {
	if s.Index < 1 {
		return fmt.Errorf("event_seq.index must be >= 1 (got %d)", s.Index)
	}
	if s.Total < 1 {
		return fmt.Errorf("event_seq.total must be >= 1 (got %d)", s.Total)
	}
	if s.Index > s.Total {
		return fmt.Errorf("event_seq.index (%d) must not exceed event_seq.total (%d)", s.Index, s.Total)
	}
	return nil
}

// IsTerminal reports whether this event is the last in its sequence.
// Single-event completions are always terminal.
func (s EventSeq) IsTerminal() bool { return s.Index == s.Total }

// RawFinding mirrors the Python RawFinding struct in
// shieldscan-api's models. Field names use snake_case JSON tags to
// match the Python Pydantic schema.
//
// Tool runners (Tasks 6.1-7.6) populate the subset of fields relevant
// to their finding type per TOOL-ARCHITECTURE.md §4.1 field-population
// matrix. Empty fields are omitted from JSON via the omitempty tags
// to keep payloads compact (relevant to ADR-017's 5MB Option-C
// trigger).
type RawFinding struct {
	// Identity
	ToolName       string `json:"tool_name"`
	EngineCategory string `json:"engine_category"`
	ScanID         string `json:"scan_id,omitempty"`
	OrgID          string `json:"org_id,omitempty"`

	// Classification
	Title       string  `json:"title"`
	Description string  `json:"description,omitempty"`
	Severity    string  `json:"severity"`
	FindingType string  `json:"finding_type"`
	CWEID       string  `json:"cwe_id,omitempty"`
	OWASP       string  `json:"owasp,omitempty"`
	CVSSScore   float64 `json:"cvss_score,omitempty"`

	// Evidence (web/API)
	TargetURL string `json:"target_url,omitempty"`
	Parameter string `json:"parameter,omitempty"`
	Payload   string `json:"payload,omitempty"`
	Request   string `json:"request,omitempty"`
	Response  string `json:"response,omitempty"`

	// Evidence (source code)
	CodeFile    string `json:"code_file,omitempty"`
	CodeLine    int    `json:"code_line,omitempty"`
	CodeSnippet string `json:"code_snippet,omitempty"`

	// Evidence (mobile)
	MobileOS      string `json:"mobile_os,omitempty"`
	Permission    string `json:"permission,omitempty"`
	ComponentName string `json:"component_name,omitempty"`

	// Evidence (SSL/TLS)
	CipherSuite string `json:"cipher_suite,omitempty"`
	CertSubject string `json:"cert_subject,omitempty"`

	// Metadata
	RawOutputRef string `json:"raw_output_ref,omitempty"`
	DiscoveredAt string `json:"discovered_at,omitempty"` // RFC3339
	Fingerprint  string `json:"fingerprint,omitempty"`
}

// JobCompletedEvent matches SPEC §7.3 job_completed event schema
// (post-ADR-017 patch). Carries findings inline + EventSeq for
// sequenced batches.
type JobCompletedEvent struct {
	EventType      EventType    `json:"event_type"` // job_completed | partial_findings
	JobID          string       `json:"job_id"`
	ScanID         string       `json:"scan_id"`
	Engine         string       `json:"engine"`
	Status         string       `json:"status"` // completed | partial | partial_findings | failed | canceled
	FindingCount   int          `json:"finding_count,omitempty"`
	DurationMs     int          `json:"duration_ms,omitempty"`
	IdempotencyKey string       `json:"idempotency_key,omitempty"`
	Timestamp      string       `json:"timestamp"`
	Findings       []RawFinding `json:"findings,omitempty"`
	EventSeq       EventSeq     `json:"event_seq"`
	ErrorMessage   string       `json:"error_message,omitempty"` // for failed events
}

// Validate checks JobCompletedEvent invariants beyond JSON shape.
// Called by Decode helpers; producers should also call before publish.
func (e *JobCompletedEvent) Validate() error {
	if e.EventType != EventJobCompleted && e.EventType != EventPartialFindings {
		return fmt.Errorf("invalid event_type for JobCompletedEvent: %q", e.EventType)
	}
	if e.JobID == "" {
		return errors.New("job_id is required")
	}
	if e.ScanID == "" {
		return errors.New("scan_id is required")
	}
	if e.Engine == "" {
		return errors.New("engine is required")
	}
	if err := e.EventSeq.Validate(); err != nil {
		return err
	}
	if len(e.Findings) > MaxFindingsPerEvent {
		return fmt.Errorf("findings count %d exceeds MaxFindingsPerEvent %d (ADR-017 — split into multiple events)",
			len(e.Findings), MaxFindingsPerEvent)
	}
	// Intermediate events (Index < Total) MUST use partial_findings status.
	if !e.EventSeq.IsTerminal() && e.EventType != EventPartialFindings {
		return fmt.Errorf("non-terminal sequenced event (index %d of %d) must use event_type=%q (got %q)",
			e.EventSeq.Index, e.EventSeq.Total, EventPartialFindings, e.EventType)
	}
	return nil
}

// CancelEvent matches SPEC §7.4 cancel_requested schema.
type CancelEvent struct {
	EventType EventType `json:"event_type"` // cancel_requested
	ScanID    string    `json:"scan_id"`
	Reason    string    `json:"reason"`
	Timestamp string    `json:"timestamp"`
}

// DecodeJobCompletedEvent parses a JSON payload into JobCompletedEvent
// with DisallowUnknownFields enabled (ADR-017 forcing function for the
// extra="forbid" discipline transferred from M4 Python Pydantic).
func DecodeJobCompletedEvent(data []byte) (*JobCompletedEvent, error) {
	var ev JobCompletedEvent
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ev); err != nil {
		return nil, fmt.Errorf("decode JobCompletedEvent: %w", err)
	}
	if err := ev.Validate(); err != nil {
		return nil, err
	}
	return &ev, nil
}

// DecodeCancelEvent parses a JSON payload into CancelEvent with
// DisallowUnknownFields enabled.
func DecodeCancelEvent(data []byte) (*CancelEvent, error) {
	var ev CancelEvent
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&ev); err != nil {
		return nil, fmt.Errorf("decode CancelEvent: %w", err)
	}
	return &ev, nil
}
