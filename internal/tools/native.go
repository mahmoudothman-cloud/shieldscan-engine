package tools

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"

	"github.com/odyssey/shieldscan-engine/internal/events"
)

// DefaultNativeTimeout is the fallback timeout when neither
// NativeRunner.Timeout nor cfg.Timeout is set. 30 minutes covers the
// longest expected single-tool run (deep Nuclei against a large
// target); shorter individual timeouts apply per TOOL-ARCHITECTURE.md
// §6 when tools opt in.
const DefaultNativeTimeout = 30 * time.Minute

// DefaultMaxStdoutBytes is the default cap for subprocess stdout.
// 50MB covers expected ranges for every native tool in M6 (deep
// Nuclei JSONL ~10-30MB, Trivy SCA ~20-30MB on monorepos) with
// generous headroom. Override per-tool via NativeRunner.MaxStdoutBytes
// if a specific tool legitimately exceeds; see field godoc for the
// override-vs-refactor decision.
const DefaultMaxStdoutBytes = 50 * 1024 * 1024 // 50 MiB

// NativeRunner wraps a single subprocess invocation as a ToolRunner.
// Each M6 native tool task constructs an instance with its own
// BuildArgs / ParseOutput closures; the lifecycle (subprocess spawn,
// stdout capture, timeout, cancellation, fingerprint enrichment) is
// shared.
//
// Functional configuration via BuildArgs/ParseOutput keeps the
// runner generic. Static fields (BinaryPath, Timeout, etc.) are set
// once at construction; per-invocation tuning flows through
// ScanConfig.
type NativeRunner struct {
	// ToolName is the canonical tool name; surfaces via Name() and
	// applied to every finding's ToolName field.
	ToolName string

	// ToolCategory is the tool category per TOOL-ARCHITECTURE.md §1;
	// surfaces via Category() and applied to every finding's
	// EngineCategory field.
	ToolCategory string

	// BinaryPath is the absolute path to the tool's binary (typically
	// /usr/local/bin/<tool> after provision-worker.sh runs). Verified
	// at worker startup (Task 5.6).
	BinaryPath string

	// BuildArgs constructs the command-line arguments for a given
	// target + scan config. The closure has full freedom to format
	// flags however the tool expects.
	BuildArgs func(target Target, cfg ScanConfig) []string

	// ParseOutput interprets subprocess stdout into normalized
	// findings. ParseOutput should NOT populate ToolName,
	// EngineCategory, DiscoveredAt, or Fingerprint — Run enriches
	// those after parsing.
	ParseOutput func(stdout []byte) ([]events.RawFinding, error)

	// Timeout is the per-tool default timeout. cfg.Timeout (if > 0)
	// overrides at job-dispatch time. If both are zero,
	// DefaultNativeTimeout applies.
	Timeout time.Duration

	// MaxStdoutBytes caps subprocess stdout to prevent runaway tools.
	// Default DefaultMaxStdoutBytes (50MB). Set to 0 to disable (not
	// recommended in production).
	//
	// Override threshold: if a tool legitimately produces >50MB stdout
	// (rare; observed only on extreme-depth Trivy SCA against giant
	// monorepos), prefer file output via tempfile pattern over raising
	// this cap. >100MB stdout approaches wire-payload concerns; tools
	// in that regime should write to disk and have the runner read the
	// file, not stream to stdout.
	MaxStdoutBytes int

	// WorkDir is the subprocess working directory. Empty means
	// inherit the parent process's CWD.
	WorkDir string

	// Env is additional environment variables for the subprocess
	// (format: "KEY=VALUE"). Inherits parent environment by default;
	// these are appended.
	Env []string

	// ExitCodeLenient controls non-zero exit code interpretation.
	// Default (zero value, false) is STRICT: non-zero exit aborts Run
	// with an error. Set true for tools that legitimately exit non-zero
	// with findings (gitleaks: exit 1 means "secrets found"; semgrep:
	// configurable). When true, ParseOutput is called regardless of
	// exit code.
	//
	// The "Lenient" naming + zero-value-strict semantic is deliberate:
	// most native tools follow exit-zero-on-clean convention; tools
	// that don't (gitleaks, semgrep) are the minority and must opt in
	// explicitly. Default-strict matches the dominant pattern.
	ExitCodeLenient bool
}

// Compile-time interface assertion. If NativeRunner ever drifts from
// the ToolRunner signature, `go build` fails before tests run.
var _ ToolRunner = (*NativeRunner)(nil)

// Name returns the configured tool name.
func (n *NativeRunner) Name() string { return n.ToolName }

// Category returns the configured tool category.
func (n *NativeRunner) Category() string { return n.ToolCategory }

// Run executes the subprocess and returns enriched findings.
// See ToolRunner.Run docstring for error semantics.
func (n *NativeRunner) Run(ctx context.Context, target Target, cfg ScanConfig) ([]events.RawFinding, error) {
	if n.BuildArgs == nil {
		return nil, fmt.Errorf("%s: BuildArgs is nil", n.ToolName)
	}
	if n.ParseOutput == nil {
		return nil, fmt.Errorf("%s: ParseOutput is nil", n.ToolName)
	}

	effectiveTimeout := n.effectiveTimeout(cfg)
	runCtx, cancel := context.WithTimeout(ctx, effectiveTimeout)
	defer cancel()

	args := n.BuildArgs(target, cfg)

	// ADR-021 Rule 1: subprocess via exec.CommandContext.
	//
	// gosec G204 suppression: BinaryPath is operator-controlled config
	// (validated at worker startup, Task 5.6) and args are constructed
	// by trusted in-repo BuildArgs closures (M6 task code, not user
	// input). The runner is the subprocess primitive; spawning
	// subprocesses is its purpose. Job payload values reaching args
	// are validated by the Python orchestrator before dispatch + by
	// the BuildArgs closure for shape (e.g., URL parsing). End-user
	// input never reaches here unsanitized.
	cmd := exec.CommandContext(runCtx, n.BinaryPath, args...) //nolint:gosec // G204: see comment above
	if n.WorkDir != "" {
		cmd.Dir = n.WorkDir
	}
	if len(n.Env) > 0 {
		// Append to inherited env so the child sees both PATH/HOME etc.
		// and our additions.
		base := cmd.Environ()
		cmd.Env = append(base, n.Env...)
	}

	maxBytes := n.MaxStdoutBytes
	if maxBytes == 0 {
		maxBytes = DefaultMaxStdoutBytes
	}
	stdout := newCappedBuffer(maxBytes)
	stderr := &bytes.Buffer{}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	runErr := cmd.Run()

	// Caller cancellation takes precedence over our internal timeout.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	// Internal timeout (cfg.Timeout / NativeRunner.Timeout / default).
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return nil, fmt.Errorf("%s timed out after %s", n.ToolName, effectiveTimeout)
	}
	// Stdout cap exceeded mid-run.
	if errors.Is(stdout.err, errStdoutCap) {
		return nil, fmt.Errorf("%s: stdout exceeded cap of %d bytes", n.ToolName, maxBytes)
	}

	// Subprocess error (non-zero exit, binary not found, etc.).
	if runErr != nil {
		// Distinguish "binary not found" from runtime errors.
		var execErr *exec.Error
		if errors.As(runErr, &execErr) {
			return nil, fmt.Errorf("%s: %w", n.ToolName, runErr)
		}
		if !n.ExitCodeLenient {
			return nil, fmt.Errorf("%s exited non-zero: %w (stderr: %s)",
				n.ToolName, runErr, truncate(stderr.String(), 512))
		}
		// ExitCodeLenient: fall through to parse stdout regardless.
	}

	findings, err := n.ParseOutput(stdout.buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("%s parse failed: %w (stderr: %s)",
			n.ToolName, err, truncate(stderr.String(), 512))
	}

	now := time.Now().UTC().Format(time.RFC3339)
	for i := range findings {
		findings[i].ToolName = n.ToolName
		findings[i].EngineCategory = n.ToolCategory
		findings[i].DiscoveredAt = now
		findings[i].Fingerprint = ComputeFingerprint(findings[i])
	}
	return findings, nil
}

// effectiveTimeout resolves the timeout precedence:
//
//	cfg.Timeout (if > 0)  →  NativeRunner.Timeout (if > 0)  →  DefaultNativeTimeout
func (n *NativeRunner) effectiveTimeout(cfg ScanConfig) time.Duration {
	if cfg.Timeout > 0 {
		return time.Duration(cfg.Timeout) * time.Second
	}
	if n.Timeout > 0 {
		return n.Timeout
	}
	return DefaultNativeTimeout
}

// truncate returns s truncated to n bytes with "..." appended if cut.
// Used for stderr context in error messages so a tool dumping
// megabytes to stderr doesn't blow up the error string.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// errStdoutCap is the sentinel for cappedBuffer overflow.
var errStdoutCap = errors.New("stdout cap exceeded")

// cappedBuffer is an io.Writer that fails Write once its byte limit
// is exceeded. The first overflowing Write records errStdoutCap;
// subsequent Writes also fail. cmd.Run propagates the Write error,
// causing exec to return ErrInvalidWrite or similar; we detect the
// cap-exceeded case via the recorded err field.
type cappedBuffer struct {
	buf bytes.Buffer
	cap int
	err error
}

func newCappedBuffer(cap int) *cappedBuffer {
	return &cappedBuffer{cap: cap}
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	if c.cap > 0 && c.buf.Len()+len(p) > c.cap {
		c.err = errStdoutCap
		return 0, c.err
	}
	return c.buf.Write(p)
}
