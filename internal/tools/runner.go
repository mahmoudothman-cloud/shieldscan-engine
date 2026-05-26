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
// Three concrete ToolRunner implementations exist:
//
//   - NativeRunner (M5.2 + ADR-023 OutputFile mode):
//     subprocess wrapper for native CLI binaries (Nuclei, Semgrep,
//     Gitleaks, SSLyze, Dep-Check, Checkov, Nikto, Wapiti, CORStest).
//     Lives at internal/tools/native.go.
//
//   - DockerRunner (M7.5a + ADR-026):
//     warm-pool wrapper for short-lived CLI-shaped Docker tools
//     (Trivy, Nmap, SQLMap). Containers are pre-warmed lazily;
//     reused with cleanup hook between checkouts. Lives at
//     internal/tools/docker/dockerrunner.go.
//
//   - DockerServiceRunner (Task 7.5b + ADR-006 + ADR-008):
//     HTTP-API wrapper for persistent Docker services (MobSF, ZAP).
//     Long-lived service containers; runner makes HTTP requests.
//     Lives at internal/tools/docker/service/. Replaces the M5.3-era
//     internal/tools/docker_service.go (deleted as part of Task 7.5b
//     Phase 4 atomic commit; zero active consumers per Phase 0.5
//     verification).
//
// Per Option β resolution at M7.5a brainstorming: Trivy + SQLMap
// route through DockerRunner (warm pool semantics fit short-lived
// CLI invocations) NOT through DockerServiceRunner. The pre-M7.5a
// docstring listed them under DockerServiceRunner; that listing was
// stale and is corrected here per ADR-026 consumer assignments.
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

	// SignedFetchURL is the pre-signed HTTPS GET URL for the mobile
	// binary upload, generated by the orchestrator per MobSF R2
	// pre-signed URL task (shieldscan-docs b25e9ba design + 8f71b01
	// SPEC ADR-013/ADR-014 R2 addendums + shieldscan-api 824853c
	// orchestrator dispatch+audit). Q1 (β) sibling-field to
	// MobileUploadRef. When present and non-empty, the MobSF consumer
	// prefers this via plain HTTP GET (no worker-side R2 credentials
	// required); falls back to MobileUploadRef r2:// path via worker
	// R2 SDK when absent/empty per Q3 (a) backward-compat migration
	// window. Populated by jobDispatchToTarget from
	// JobMobileConfig.SignedFetchURL.
	SignedFetchURL string

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
	// JSON tag added per Task 7.3 Q6 lock — wire-payload deserialization.
	AuthConfig *AuthConfig `json:"auth_config,omitempty"`
}

// AuthConfig describes decrypted authentication material for tools
// that support authenticated scans. Per SPECIFICATION §7.1 auth block.
// JSON tags added per Task 7.3 Q6 lock — first consumer (ZAP) deserializes
// from wire payload via these tags. Pre-existing field set preserved
// (5 Type values + Fields map) per Task 7.3 Phase 1 D1 deviation.
type AuthConfig struct {
	// Type is one of: "cookie" | "bearer" | "basic" | "custom_header" |
	// "form".
	Type string `json:"type"`

	// Data is the credential value, already decrypted by the processor.
	// Format depends on Type:
	//   cookie       → "name=value; name2=value2"
	//   bearer       → token (bare; runner adds "Bearer " prefix)
	//   basic        → "user:pass"
	//   custom_header → "Header-Name: value"
	Data string `json:"data"`

	// Fields carries form-auth field names and values. Used only when
	// Type == "form".
	Fields map[string]string `json:"fields,omitempty"`
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

	// Ports is the Nmap-specific port range specification (e.g., "80,443"
	// or "1-65535"). Empty or "top-1000" defaults to Nmap's top 1000
	// most common ports. Ignored by non-Nmap tools.
	// Per ADR-026 + Task 7.2 design (plans/2026-05-06-task-7.2-nmap-design.md
	// in shieldscan-docs).
	Ports string

	// AllowPrivateTargets permits scanning RFC1918 ranges (10.0.0.0/8,
	// 172.16.0.0/12, 192.168.0.0/16). Defaults false. Tenant-controllable
	// for legitimate internal-network scanning with VPN/peered worker
	// access. Layer 3 defense-in-depth flag; Layer 1 (shieldscan-api
	// tenant target ownership validation) remains required precondition.
	// Currently consumed by Nmap; future Docker tool consumers may inherit.
	AllowPrivateTargets bool

	// ExtraArgs is an escape hatch for tool-specific tuning that
	// doesn't warrant a top-level field. Nuclei: "rate-limit-minute"
	// override. Wapiti: "scope" tuning. Etc.
	ExtraArgs map[string]string
}
