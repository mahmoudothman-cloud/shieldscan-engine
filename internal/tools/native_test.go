package tools

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/odyssey/shieldscan-engine/internal/events"
)

// Test binaries used: /bin/echo, /bin/true, /bin/false, /bin/sleep,
// /bin/cat. All POSIX-portable; CI runs on ubuntu-24.04 (engine.yml).
//
// Platform note: Ubuntu's /bin/echo is GNU coreutils; macOS uses BSD
// echo with subtly different flag handling. Tests below avoid -e/-n
// flags so the GNU/BSD difference doesn't surface. If you run tests
// on macOS locally, output should still match.

// TestMain wires goleak.VerifyTestMain per ADR-021 ctx-discipline.
// NativeRunner.Run does not spawn goroutines directly, but cancellation
// tests below leak watchdog goroutines if not torn down properly.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// helpers ---------------------------------------------------------

// echoRunner builds a NativeRunner around /bin/echo with the given
// stdout-to-finding mapping. Used by happy-path tests.
func echoRunner(name, cat string, args []string, parse func([]byte) ([]events.RawFinding, error)) *NativeRunner {
	return &NativeRunner{
		ToolName:     name,
		ToolCategory: cat,
		BinaryPath:   "/bin/echo",
		BuildArgs:    func(Target, ScanConfig) []string { return args },
		ParseOutput:  parse,
		Timeout:      5 * time.Second,
	}
}

// trimmedTitle is the canonical "stdout becomes a single finding"
// ParseOutput closure used across happy-path tests.
func trimmedTitle(out []byte) ([]events.RawFinding, error) {
	return []events.RawFinding{{
		Title:       strings.TrimSpace(string(out)),
		FindingType: "test",
		Severity:    "info",
	}}, nil
}

// tests -----------------------------------------------------------

// TestNativeRunner_ImplementsToolRunner is the runtime counterpart to
// the compile-time `var _ ToolRunner = (*NativeRunner)(nil)` assertion
// in native.go. Pins both directions: signature stability + the fact
// that the assertion line exists.
func TestNativeRunner_ImplementsToolRunner(t *testing.T) {
	var r ToolRunner = &NativeRunner{ToolName: "x", ToolCategory: "y"}
	assert.Equal(t, "x", r.Name())
	assert.Equal(t, "y", r.Category())
}

// TestNativeRunner_ExecutesEcho is the canonical happy path. /bin/echo
// produces "hello\n" on stdout; ParseOutput trims to "hello"; runner
// returns one finding with Title="hello".
func TestNativeRunner_ExecutesEcho(t *testing.T) {
	r := echoRunner("echo", "test", []string{"hello"}, trimmedTitle)
	findings, err := r.Run(t.Context(), Target{URL: "http://test.example.com"}, ScanConfig{})
	require.NoError(t, err)
	require.Len(t, findings, 1)
	assert.Equal(t, "hello", findings[0].Title)
}

// TestNativeRunner_PopulatesIdentity verifies enrichment after parse:
// every returned finding gets ToolName, EngineCategory, DiscoveredAt,
// and Fingerprint populated by the runner (NOT by ParseOutput).
func TestNativeRunner_PopulatesIdentity(t *testing.T) {
	r := echoRunner("echo", "test", []string{"a"}, func([]byte) ([]events.RawFinding, error) {
		// Two findings; ParseOutput leaves enrichment fields empty.
		return []events.RawFinding{
			{Title: "first", FindingType: "test"},
			{Title: "second", FindingType: "test"},
		}, nil
	})

	findings, err := r.Run(t.Context(), Target{}, ScanConfig{})
	require.NoError(t, err)
	require.Len(t, findings, 2)

	for i, f := range findings {
		assert.Equal(t, "echo", f.ToolName, "finding %d ToolName", i)
		assert.Equal(t, "test", f.EngineCategory, "finding %d Category", i)
		assert.NotEmpty(t, f.DiscoveredAt, "finding %d DiscoveredAt", i)
		assert.NotEmpty(t, f.Fingerprint, "finding %d Fingerprint", i)

		// DiscoveredAt should parse as RFC3339.
		_, parseErr := time.Parse(time.RFC3339, f.DiscoveredAt)
		assert.NoError(t, parseErr, "finding %d DiscoveredAt format", i)
	}
}

// TestNativeRunner_AppliesFingerprint pins that the runner applies
// the canonical ComputeFingerprint algorithm (no shortcuts, no
// alternate hash). Builds findings with controlled inputs, runs, and
// asserts the Fingerprint matches a fresh ComputeFingerprint call.
func TestNativeRunner_AppliesFingerprint(t *testing.T) {
	r := echoRunner("echo", "test", []string{"x"}, func([]byte) ([]events.RawFinding, error) {
		return []events.RawFinding{{
			FindingType: "xss", TargetURL: "https://app.example.com", Parameter: "q",
		}}, nil
	})
	findings, err := r.Run(t.Context(), Target{}, ScanConfig{})
	require.NoError(t, err)
	require.Len(t, findings, 1)

	// Recompute against the post-enrichment finding (ToolName etc.
	// are part of the fingerprint input).
	expected := ComputeFingerprint(findings[0])
	// Note: ComputeFingerprint includes Fingerprint? No — only the 6
	// listed components. Recomputing on the enriched finding yields
	// the same value since enrichment doesn't change those 6.
	assert.Equal(t, expected, findings[0].Fingerprint)
	// And to be sure: it MUST equal the value of running fingerprint
	// against a finding with just the contributing fields populated.
	independent := ComputeFingerprint(events.RawFinding{
		ToolName:    "echo",
		FindingType: "xss",
		TargetURL:   "https://app.example.com",
		Parameter:   "q",
	})
	assert.Equal(t, independent, findings[0].Fingerprint)
}

// TestNativeRunner_EmptyOutputIsValid pins that a tool finding nothing
// is NOT an error. /bin/true exits 0 with no stdout; ParseOutput
// returns ([], nil); runner returns ([], nil).
func TestNativeRunner_EmptyOutputIsValid(t *testing.T) {
	r := &NativeRunner{
		ToolName: "true", ToolCategory: "test",
		BinaryPath: "/bin/true",
		BuildArgs:  func(Target, ScanConfig) []string { return nil },
		ParseOutput: func(out []byte) ([]events.RawFinding, error) {
			assert.Empty(t, out, "no stdout from /bin/true")
			return nil, nil
		},
		Timeout: 5 * time.Second,
	}
	findings, err := r.Run(t.Context(), Target{}, ScanConfig{})
	require.NoError(t, err)
	assert.Empty(t, findings)
}

// TestNativeRunner_TimeoutKillsSubprocess verifies that
// NativeRunner.Timeout sends SIGKILL to the subprocess when the
// timeout elapses, and Run returns a descriptive timeout error.
//
// Uses /bin/sleep 5 with a 100ms timeout. Bounded test runtime via
// context.WithTimeout(t.Context(), 1*time.Second) wrapping the call;
// if the subprocess weren't killed, the outer ctx would expire with
// ctx.DeadlineExceeded — the test would still fail but with a less
// useful error.
func TestNativeRunner_TimeoutKillsSubprocess(t *testing.T) {
	r := &NativeRunner{
		ToolName: "sleep", ToolCategory: "test",
		BinaryPath:  "/bin/sleep",
		BuildArgs:   func(Target, ScanConfig) []string { return []string{"5"} },
		ParseOutput: func([]byte) ([]events.RawFinding, error) { return nil, nil },
		Timeout:     100 * time.Millisecond,
	}

	start := time.Now()
	outerCtx, outerCancel := context.WithTimeout(t.Context(), time.Second)
	defer outerCancel()

	_, err := r.Run(outerCtx, Target{}, ScanConfig{})
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out", "should surface timeout in error")
	assert.Less(t, elapsed, 500*time.Millisecond,
		"runner should return promptly after subprocess kill, not wait for /bin/sleep 5")
}

// TestNativeRunner_ContextCancelKillsSubprocess verifies caller-side
// cancellation: parent ctx canceled mid-run kills the subprocess and
// Run returns ctx.Err() (context.Canceled).
func TestNativeRunner_ContextCancelKillsSubprocess(t *testing.T) {
	r := &NativeRunner{
		ToolName: "sleep", ToolCategory: "test",
		BinaryPath:  "/bin/sleep",
		BuildArgs:   func(Target, ScanConfig) []string { return []string{"5"} },
		ParseOutput: func([]byte) ([]events.RawFinding, error) { return nil, nil },
		Timeout:     10 * time.Second, // long; cancellation should win first
	}

	ctx, cancel := context.WithCancel(t.Context())

	// Cancel after 50ms. Use a ctx-aware sleep so the cancel goroutine
	// itself respects test cleanup (ADR-021 Rule 2).
	done := make(chan struct{})
	go func() {
		defer close(done)
		select {
		case <-ctx.Done():
		case <-time.After(50 * time.Millisecond):
			cancel()
		}
	}()

	start := time.Now()
	_, err := r.Run(ctx, Target{}, ScanConfig{})
	elapsed := time.Since(start)
	<-done // ensure cancel goroutine exits before TestMain's goleak check

	require.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled),
		"expected context.Canceled, got: %v", err)
	assert.Less(t, elapsed, 500*time.Millisecond,
		"subprocess should die promptly on ctx cancel")
}

// TestNativeRunner_NonZeroExitStrictDefault pins the strict default:
// ExitCodeLenient is false (zero value), so /bin/false's exit code 1
// surfaces as an error. This is the behavior most native tools want
// (Nuclei, Subfinder, SSLyze, etc. — exit zero on clean).
func TestNativeRunner_NonZeroExitStrictDefault(t *testing.T) {
	r := &NativeRunner{
		ToolName: "false", ToolCategory: "test",
		BinaryPath:  "/bin/false",
		BuildArgs:   func(Target, ScanConfig) []string { return nil },
		ParseOutput: func([]byte) ([]events.RawFinding, error) { return nil, nil },
		Timeout:     5 * time.Second,
		// ExitCodeLenient deliberately not set — zero value (false) = strict.
	}
	_, err := r.Run(t.Context(), Target{}, ScanConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exited non-zero")
}

// TestNativeRunner_NonZeroExitLenient covers the gitleaks pattern:
// non-zero exit means "findings exist", not an error. ExitCodeLenient
// is true; ParseOutput is called regardless of exit code; findings
// flow through.
func TestNativeRunner_NonZeroExitLenient(t *testing.T) {
	r := &NativeRunner{
		ToolName: "false", ToolCategory: "secrets",
		BinaryPath: "/bin/false",
		BuildArgs:  func(Target, ScanConfig) []string { return nil },
		ParseOutput: func(out []byte) ([]events.RawFinding, error) {
			// Simulating: ParseOutput chose to ignore exit code and
			// produce a synthetic finding.
			return []events.RawFinding{{
				Title: "secret found", FindingType: "hardcoded-secret", Severity: "critical",
			}}, nil
		},
		Timeout:         5 * time.Second,
		ExitCodeLenient: true,
	}
	findings, err := r.Run(t.Context(), Target{}, ScanConfig{})
	require.NoError(t, err, "ExitCodeLenient=true should not error on non-zero exit")
	require.Len(t, findings, 1)
	assert.Equal(t, "secret found", findings[0].Title)
}

// TestNativeRunner_BinaryNotFound pins behavior when the configured
// BinaryPath does not exist. exec returns *exec.Error before any
// subprocess starts; runner wraps it with the tool name.
func TestNativeRunner_BinaryNotFound(t *testing.T) {
	r := &NativeRunner{
		ToolName: "nonexistent", ToolCategory: "test",
		BinaryPath:  "/usr/local/bin/this-binary-definitely-does-not-exist",
		BuildArgs:   func(Target, ScanConfig) []string { return nil },
		ParseOutput: func([]byte) ([]events.RawFinding, error) { return nil, nil },
		Timeout:     5 * time.Second,
	}
	_, err := r.Run(t.Context(), Target{}, ScanConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent")
}

// TestNativeRunner_ParseErrorPropagated pins that errors from the
// ParseOutput closure surface as Run errors with stderr context.
func TestNativeRunner_ParseErrorPropagated(t *testing.T) {
	r := echoRunner("echo", "test", []string{"x"}, func([]byte) ([]events.RawFinding, error) {
		return nil, errors.New("synthetic parse error")
	})
	_, err := r.Run(t.Context(), Target{}, ScanConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "echo parse failed")
	assert.Contains(t, err.Error(), "synthetic parse error")
}

// TestNativeRunner_StdoutSizeCap pins the DoS guard: tools producing
// stdout beyond MaxStdoutBytes fail without attempting to parse.
//
// Production default is 50MB (DefaultMaxStdoutBytes). Test uses 1KB
// cap with 4KB output to avoid slow CI; the mechanism is the same
// regardless of the absolute value.
func TestNativeRunner_StdoutSizeCap(t *testing.T) {
	// /bin/cat reads stdin and writes to stdout. We use it as a
	// controllable stdout source via a shell-piped large input.
	// Simpler: use printf-equivalent via a short command.
	// We use 'yes' which prints "y\n" repeatedly.
	r := &NativeRunner{
		ToolName: "yes", ToolCategory: "test",
		BinaryPath: "/usr/bin/yes",
		BuildArgs:  func(Target, ScanConfig) []string { return nil },
		ParseOutput: func([]byte) ([]events.RawFinding, error) {
			t.Fatal("ParseOutput must NOT be called when stdout cap is exceeded")
			return nil, nil
		},
		Timeout:         200 * time.Millisecond, // safety net; cap should fire first
		MaxStdoutBytes:  1024,                   // 1KB
		ExitCodeLenient: true,                   // 'yes' is killed; lenient avoids exit-code noise
	}
	_, err := r.Run(t.Context(), Target{}, ScanConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "stdout exceeded cap")
}

// TestNativeRunner_ReturnsUnboundedFindings is the ADR-017 forward-pin:
// the runner returns whatever ParseOutput produced, without applying
// any cap. Cap enforcement is the processor's responsibility (Task 5.5).
//
// Synthesizes 1500 findings (above events.MaxFindingsPerEvent = 1000)
// and verifies all 1500 are returned by the runner.
func TestNativeRunner_ReturnsUnboundedFindings(t *testing.T) {
	r := &NativeRunner{
		ToolName: "echo", ToolCategory: "test",
		BinaryPath: "/bin/echo",
		BuildArgs:  func(Target, ScanConfig) []string { return []string{"x"} },
		ParseOutput: func([]byte) ([]events.RawFinding, error) {
			out := make([]events.RawFinding, 1500)
			for i := range out {
				out[i].FindingType = "test"
				out[i].Severity = "info"
			}
			return out, nil
		},
		Timeout: 5 * time.Second,
	}
	findings, err := r.Run(t.Context(), Target{}, ScanConfig{})
	require.NoError(t, err)
	assert.Len(t, findings, 1500,
		"runner does NOT enforce events.MaxFindingsPerEvent cap (ADR-017 — that's the processor's job at Task 5.5)")
}

// TestNativeRunner_CfgTimeoutOverride pins the timeout precedence:
// cfg.Timeout (when > 0) overrides NativeRunner.Timeout. Uses
// /bin/sleep 1 with NativeRunner.Timeout=10s but cfg.Timeout=1
// (1 second nominal — but seconds are coarse for tests). To keep the
// test fast we use cfg.Timeout=1 (= 1 second) and verify the runner
// returns a timeout error well before /bin/sleep 1 would naturally
// finish — which is impossible since 1s < 1s. So we use sleep 5 and
// cfg.Timeout=1 (stays under the 10s tool default).
//
// Effective: cfg.Timeout=1s overrides Timeout=10s; /bin/sleep 5 is
// killed at ~1s with timeout error.
func TestNativeRunner_CfgTimeoutOverride(t *testing.T) {
	r := &NativeRunner{
		ToolName: "sleep", ToolCategory: "test",
		BinaryPath:  "/bin/sleep",
		BuildArgs:   func(Target, ScanConfig) []string { return []string{"5"} },
		ParseOutput: func([]byte) ([]events.RawFinding, error) { return nil, nil },
		Timeout:     10 * time.Second, // long — should be overridden
	}

	start := time.Now()
	_, err := r.Run(t.Context(), Target{}, ScanConfig{Timeout: 1})
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out", "cfg.Timeout=1s should fire before /bin/sleep 5 finishes")
	assert.Less(t, elapsed, 2*time.Second,
		"cfg.Timeout=1s should kill subprocess at ~1s, well before /bin/sleep 5 finishes")
}

// TestNativeRunner_NilBuildArgs pins the contract surface: BuildArgs
// must be set or Run returns an error. Catches construction-time bugs
// that would otherwise surface as obscure subprocess errors.
func TestNativeRunner_NilBuildArgs(t *testing.T) {
	r := &NativeRunner{
		ToolName: "x", ToolCategory: "test",
		BinaryPath: "/bin/echo",
		// BuildArgs deliberately nil
		ParseOutput: trimmedTitle,
		Timeout:     5 * time.Second,
	}
	_, err := r.Run(t.Context(), Target{}, ScanConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "BuildArgs is nil")
}

// TestNativeRunner_NilParseOutput pins the symmetric contract: nil
// ParseOutput is rejected at Run entry.
func TestNativeRunner_NilParseOutput(t *testing.T) {
	r := &NativeRunner{
		ToolName: "x", ToolCategory: "test",
		BinaryPath: "/bin/echo",
		BuildArgs:  func(Target, ScanConfig) []string { return []string{"x"} },
		// ParseOutput deliberately nil
		Timeout: 5 * time.Second,
	}
	_, err := r.Run(t.Context(), Target{}, ScanConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ParseOutput is nil")
}
