// Package tools defines the universal ToolRunner contract every M6
// native tool runner and M7 Docker service runner implements.
//
// The processor (Task 5.5) never branches on tool type — it calls
// ToolRunner.Run() and treats every tool identically. Tool-specific
// invocation, output parsing, and error handling are encapsulated in
// the runner's BuildArgs / ParseOutput closures.
//
// Architectural commitments enforced here:
//   - ADR-013: runners produce findings (return []events.RawFinding);
//     they never persist them. Processor packages findings into
//     job_completed events for the Python sole writer.
//   - ADR-017: runners return unbounded slices; the processor applies
//     events.MaxFindingsPerEvent and event_seq sequencing.
//   - ADR-021: ctx propagation is mandatory. Run takes ctx and
//     subprocesses spawn via exec.CommandContext.
//
// Concrete implementations:
//   - NativeRunner (this package, Task 5.2) — subprocess wrapper for
//     binaries on the worker filesystem (Nuclei, Semgrep, Subfinder,
//     etc.).
//   - DockerServiceRunner (Task 5.3) — HTTP API wrapper for persistent
//     Docker services (MobSF, ZAP, Trivy, SQLMap).
package tools

import (
	"context"

	"github.com/odyssey/shieldscan-engine/internal/events"
)

// ToolRunner is the universal contract every scan tool implements.
//
// Run executes the tool against target with cfg, returning all findings
// produced. Errors fall into three categories:
//
//   - Caller-driven cancellation. ctx.Err() returned directly when the
//     caller cancels or the parent context expires.
//   - Tool-internal timeout. Implementations may impose their own
//     timeout (NativeRunner.Timeout); when that elapses, an error
//     describing the timeout is returned.
//   - Tool execution / parse error. Subprocess failed in a way the
//     parser considers fatal, OR ParseOutput returned an error.
//
// A tool finding nothing is NOT an error — Run returns ([], nil).
//
// ADR-021: Run MUST honor ctx cancellation throughout. Subprocesses
// spawned during Run MUST use exec.CommandContext (or equivalent)
// so they terminate when ctx is canceled.
type ToolRunner interface {
	// Name returns the canonical tool name (e.g., "nuclei", "mobsf").
	// Used as the tool registry key (M6.8) and as the ToolName field
	// applied to every finding produced by Run.
	Name() string

	// Category returns the tool category per TOOL-ARCHITECTURE.md §1:
	//   "dast" | "sast" | "mobile" | "ssl" | "recon" |
	//   "infrastructure" | "secrets" | "sca" | "api" |
	//   "container" | "iac"
	// Applied as the EngineCategory field on every finding.
	Category() string

	// Run executes the tool. See type-level docstring for error
	// semantics. Findings are returned with the following enrichments
	// applied by the runner (NOT by ParseOutput):
	//   - ToolName       (from Name())
	//   - EngineCategory (from Category())
	//   - DiscoveredAt   (RFC3339 UTC, set at enrichment time)
	//   - Fingerprint    (computed via ComputeFingerprint)
	//
	// ScanID and OrgID are populated by the processor (Task 5.5) when
	// the job carries them; runners leave those fields empty.
	Run(ctx context.Context, target Target, cfg ScanConfig) ([]events.RawFinding, error)
}

// Target identifies what a tool should scan. Per TOOL-ARCHITECTURE.md
// §3.2; mobile-specific fields are present for forward-compatibility
// with M7.1 MobSF without retroactive struct extension.
type Target struct {
	// URL is the primary endpoint for web scans (DAST, SSL, recon).
	URL string

	// Domain is the root domain for recon-tier tools (Subfinder,
	// httpx). Web scans typically derive Domain from URL but may
	// override.
	Domain string

	// TargetType is one of: "web" | "mobile" | "container" | "source".
	// Tools self-select via this field; a runner asked to scan a
	// target_type it doesn't support should return a structured error.
	TargetType string

	// DomainVerified gates non-recon tools from accidentally scanning
	// unverified targets. Recon tools may run against unverified
	// domains for discovery; deeper tools (DAST, SAST) require
	// verification per SPECIFICATION §10.3.
	DomainVerified bool

	// MobileUploadRef is the R2 reference to an APK/IPA upload for
	// mobile scans. Format: "r2://uploads/<org_id>/<file>". Populated
	// by the processor (Task 5.5) when the job carries mobile_config;
	// empty for non-mobile tools.
	MobileUploadRef string

	// SourcePath is the local filesystem path to a source-code clone
	// (M6.2 Semgrep, M6.5 Gitleaks, M6.7 Checkov). Populated by the
	// processor; empty for non-source tools.
	SourcePath string

	// ContainerImage is the Docker image tag for container scans (M7.3
	// Trivy). Format: "repo:tag" or "repo@sha256:digest".
	ContainerImage string

	// AuthConfig carries decrypted credentials for authenticated scans.
	// nil when no authentication is configured. ADR-015 (decrypted
	// credentials in Redis transit) is reserved; this field is a
	// placeholder so M6 runners don't refactor when ADR-015 lands.
	AuthConfig *AuthConfig
}

// AuthConfig describes decrypted authentication material for tools
// that support authenticated scans. Per SPECIFICATION §7.1 auth block.
type AuthConfig struct {
	// Type is one of: "cookie" | "bearer" | "basic" | "custom_header" |
	// "form".
	Type string

	// Data is the credential value, already decrypted by the processor.
	// Format depends on Type:
	//   cookie       → "name=value; name2=value2"
	//   bearer       → token (bare; runner adds "Bearer " prefix)
	//   basic        → "user:pass"
	//   custom_header → "Header-Name: value"
	Data string

	// Fields carries form-auth field names and values. Used only when
	// Type == "form".
	Fields map[string]string
}

// ScanConfig carries per-scan tunables that may override tool defaults.
// Processor (Task 5.5) populates from the SPECIFICATION §7.1 job
// payload's config block.
type ScanConfig struct {
	// Depth is one of: "quick" | "standard" | "deep". Tools translate
	// to their own depth knobs (e.g., Nuclei template categories,
	// Wapiti scan modules).
	Depth string

	// Timeout overrides the tool's default timeout (in seconds). Zero
	// means "use tool default". NativeRunner translates Timeout > 0
	// into context.WithTimeout for the subprocess.
	Timeout int

	// MaxRPS rate-limits requests per second for DAST tools that
	// support it (Nuclei -rl, Wapiti --max-scan-time). Zero means
	// "use tool default".
	MaxRPS int

	// TemplateCategories is Nuclei-specific (M6.1) — a list of template
	// category tags ("owasp-top-10", "cves", "misconfigurations").
	// Empty for non-Nuclei tools.
	TemplateCategories []string

	// ExtraArgs is an escape hatch for tool-specific tuning that
	// doesn't warrant a top-level field. Nuclei: "rate-limit-minute"
	// override. Wapiti: "scope" tuning. Etc.
	ExtraArgs map[string]string
}
