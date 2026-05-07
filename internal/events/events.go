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
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
)

// FixtureJobDispatchPythonV1 is the canonical Python-emitted job
// dispatch payload (SPEC §7.1) used as the cross-repo wire-format pin
// in tests. See testdata/job_dispatch_python_v1.md for provenance.
//
//go:embed testdata/job_dispatch_python_v1.json
var FixtureJobDispatchPythonV1 []byte

// FixtureJobCompletedPythonV1 is the canonical job-completion event
// payload (SPEC §7.3 post-ADR-017). See testdata/job_completed_python_v1.md.
//
//go:embed testdata/job_completed_python_v1.json
var FixtureJobCompletedPythonV1 []byte

// EventType enumerates the event_type values that may appear on the
// shieldscan:* Redis primitives. Producers MUST use these constants;
// consumers MUST validate against them.
type EventType string

const (
	// Progress stream (shieldscan:progress:{scan_id})
	EventJobStarted           EventType = "job_started"
	EventReconStarted         EventType = "recon_started"
	EventSubdomainsDiscovered EventType = "subdomains_discovered"
	EventLivenessProbed       EventType = "liveness_probed" // M6.3: emitted by recon.RunRecon after httpx phase
	EventReconCompleted       EventType = "recon_completed" // M6.3: emitted by recon.RunRecon at end of pipeline
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

	// SPEC §7.3 schema extension (M6-close-followup, ADR-024).
	// Optional fields with omitempty; backward-compatible.
	// Per ADR-024 "Python ingest scope": columns-ready posture
	// (Engine emission lands; Python ingest path deferred).
	References     []string `json:"references,omitempty"`
	Tags           []string `json:"tags,omitempty"`
	CVSSVector     string   `json:"cvss_vector,omitempty"`
	AdditionalCWEs []string `json:"additional_cwes,omitempty"`

	// Metadata carries per-tool structured payload as key-value pairs.
	// Nil for tools that don't emit structured metadata. Per ADR-027
	// (lands as Phase 5 docs followup of Task 7.2).
	//
	// Currently consumed by Nmap (host, port, protocol, service, product,
	// version, extra_info, target keys); future consumers (Trivy, SQLMap,
	// ZAP, MobSF) inherit the Metadata pattern.
	//
	// M9 AI Pipeline + M8 Recon-First Pipeline consume Metadata downstream
	// for CVE matching and recon-helper input respectively.
	Metadata map[string]string `json:"metadata,omitempty"`

	// Provenance + identity
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

// JobDispatch matches SPEC §7.1 queue payload shape. The Go consumer
// (internal/redis/JobConsumer.Pop) deserializes the JSON written by
// the Python ScanQueue.dispatch (shieldscan-api scan_queue.py).
//
// Cross-repo contract: top-level field set MUST stay in sync with
// the Python emit. DisallowUnknownFields is enforced at decode time
// — any new top-level field on the Python side requires a
// corresponding addition here.
type JobDispatch struct {
	ID              string           `json:"id"`
	ScanID          string           `json:"scan_id"`
	OrganizationID  string           `json:"organization_id"`
	Engine          string           `json:"engine"`
	IdempotencyKey  string           `json:"idempotency_key"`
	Target          JobTarget        `json:"target"`
	Auth            *JobAuth         `json:"auth"`
	Config          map[string]any   `json:"config"`
	MobileConfig    *JobMobileConfig `json:"mobile_config"`
	CallbackChannel string           `json:"callback_channel"`
	CreatedAt       string           `json:"created_at"`
}

// JobTarget is the embedded target object inside JobDispatch.
type JobTarget struct {
	URL            string `json:"url"`
	TargetType     string `json:"target_type"`
	DomainVerified bool   `json:"domain_verified"`
}

// JobAuth is the optional embedded auth object inside JobDispatch.
type JobAuth struct {
	Type string `json:"type"`
	Data string `json:"data"`
}

// JobMobileConfig is the optional embedded mobile-config object.
type JobMobileConfig struct {
	UploadRef    string `json:"upload_ref"`
	Platform     string `json:"platform"`
	AnalysisType string `json:"analysis_type"`
}

// ProgressEvent is the open-ended payload type for progress events
// flowing through the shieldscan:progress:{scan_id} Stream.
//
// Loose typing (map vs typed struct) is deliberate — SPEC §7.2 has
// 7+ event variants (job_started, recon_started, subdomains_discovered,
// job_progress, finding_discovered, job_canceled, job_failed) varying
// in payload shape. A strict per-variant struct would require N Go
// types and Go-side schema work every time Python adds a variant.
// Python is map-based; SPEC is the contract surface.
//
// ProgressPublisher injects event_type / scan_id / timestamp headers;
// payload is open-ended for everything else. If type-safety pressure
// surfaces (specific variants need validation), promote those variants
// to typed structs in this package; ProgressEvent map remains the
// fallback. See engine DRIFT-LOG 2026-05-01 entry.
type ProgressEvent map[string]any

// SplitForCompletion splits findings into one or more JobCompletedEvent
// instances respecting MaxFindingsPerEvent (ADR-017).
//
// base carries per-job invariants (JobID, ScanID, Engine, Status,
// FindingCount, DurationMs, IdempotencyKey, Timestamp, ErrorMessage).
// The splitter overrides Findings + EventSeq per batch index, and
// for intermediate batches also overrides EventType, Status,
// FindingCount, DurationMs.
//
// Edge cases:
//   - 0 findings:    single event, EventSeq{1, 1}, Findings:nil
//   - <=1000:        single event, EventSeq{1, 1}
//   - 1001..2000:    two events, EventSeq{1,2} + {2,2}
//   - 2001..3000:    three events
//   - etc.
//
// Per ADR-017: intermediate events use Status="partial_findings" +
// EventType=EventPartialFindings; FindingCount and DurationMs are
// zeroed (authoritative only on the terminal event).
func SplitForCompletion(findings []RawFinding, base JobCompletedEvent) []JobCompletedEvent {
	if len(findings) <= MaxFindingsPerEvent {
		ev := base
		ev.Findings = findings
		ev.EventSeq = EventSeq{Index: 1, Total: 1}
		return []JobCompletedEvent{ev}
	}

	total := (len(findings) + MaxFindingsPerEvent - 1) / MaxFindingsPerEvent
	out := make([]JobCompletedEvent, 0, total)
	for i := 0; i < total; i++ {
		start := i * MaxFindingsPerEvent
		end := start + MaxFindingsPerEvent
		if end > len(findings) {
			end = len(findings)
		}
		ev := base
		ev.Findings = findings[start:end]
		ev.EventSeq = EventSeq{Index: i + 1, Total: total}
		if i < total-1 {
			// Intermediate batch (ADR-017).
			ev.EventType = EventPartialFindings
			ev.Status = "partial_findings"
			ev.FindingCount = 0
			ev.DurationMs = 0
		}
		// Else: terminal event preserves base's fields.
		out = append(out, ev)
	}
	return out
}

// DecodeJobDispatch parses a JSON payload into JobDispatch with
// DisallowUnknownFields enabled. Cross-repo wire-format pin: any
// new field on the Python emit side breaks decode here, forcing
// explicit struct extension.
func DecodeJobDispatch(data []byte) (*JobDispatch, error) {
	var job JobDispatch
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&job); err != nil {
		return nil, fmt.Errorf("decode JobDispatch: %w", err)
	}
	return &job, nil
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
