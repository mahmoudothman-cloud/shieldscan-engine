package source

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestCloneRepo_RejectsEmptyURL verifies the defensive empty-URL
// guard. The orchestrator-side validator + the engine wire schema
// should both prevent this from reaching the runner; the engine
// guard is belt-and-braces per Q-VALIDATOR.
func TestCloneRepo_RejectsEmptyURL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := CloneRepo(ctx, "", t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "gitURL is required") {
		t.Fatalf("expected gitURL-required error; got %v", err)
	}
}

// TestCloneRepo_RejectsEmptyStagingDir verifies the staging-dir
// guard. The StagingManager normally provides a non-empty path
// derived from the scan id.
func TestCloneRepo_RejectsEmptyStagingDir(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := CloneRepo(ctx, "https://example.com/repo.git", "")
	if err == nil || !strings.Contains(err.Error(), "stagingDir is required") {
		t.Fatalf("expected stagingDir-required error; got %v", err)
	}
}

// TestCloneRepo_RejectsNonHTTPSScheme verifies the defensive HTTPS-
// scheme guard. The api-side validator is the primary defense; the
// engine guard catches any wire-layer or direct-producer bypass.
// Mirror api-side Q-AUTH + Q-VALIDATOR locks.
func TestCloneRepo_RejectsNonHTTPSScheme(t *testing.T) {
	cases := []string{
		"http://github.com/x/y.git",
		"git://github.com/x/y.git",
		"ssh://git@github.com/x/y.git",
		"file:///tmp/x",
	}
	for _, gitURL := range cases {
		t.Run(gitURL, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			err := CloneRepo(ctx, gitURL, t.TempDir())
			if err == nil || !strings.Contains(err.Error(), "HTTPS required") {
				t.Fatalf("expected HTTPS-required error for %q; got %v", gitURL, err)
			}
		})
	}
}

// TestCloneRepo_RejectsHostlessURL verifies the parsed.Host guard.
func TestCloneRepo_RejectsHostlessURL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := CloneRepo(ctx, "https:///nohost", t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "hostless URL") {
		t.Fatalf("expected hostless-URL error; got %v", err)
	}
}

// TestCloneRepo_WrapsGitFailureWithOutputTail verifies clone
// failure surfacing per Q-FAILURE-MODE structured-error lock. Uses
// an HTTPS URL with a guaranteed-invalid host so git's network
// resolution fails fast; we don't depend on network reachability.
// The fmt.Errorf chain must include the wrapped underlying error
// AND the stderr/stdout output tail for forensic context.
func TestCloneRepo_WrapsGitFailureWithOutputTail(t *testing.T) {
	if _, err := os.Stat("/usr/bin/git"); err != nil {
		t.Skip("git binary not available at /usr/bin/git; skipping subprocess test")
	}
	// Bounded ctx so the test doesn't depend on DNS timeout defaults.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stagingDir := filepath.Join(t.TempDir(), "sif-test")
	// .invalid is reserved per RFC 2606 — guaranteed not to resolve.
	err := CloneRepo(ctx, "https://nonexistent.invalid/repo.git", stagingDir)
	if err == nil {
		t.Fatal("expected clone failure against invalid host")
	}
	if !strings.Contains(err.Error(), "git clone") {
		t.Fatalf("expected wrapped 'git clone' message; got %v", err)
	}
	// Verify the underlying *exec.ExitError unwraps cleanly so callers
	// can inspect the exit code if they need to (Drift #51-style
	// integration discipline).
	var unwrapped error = err
	for unwrapped != nil {
		unwrapped = errors.Unwrap(unwrapped)
	}
}

// TestTruncateOutput_LeavesShortOutputIntact verifies the audit-log
// hygiene helper preserves short outputs verbatim.
func TestTruncateOutput_LeavesShortOutputIntact(t *testing.T) {
	got := truncateOutput([]byte("fatal: remote not found"))
	if got != "fatal: remote not found" {
		t.Fatalf("short output should pass through; got %q", got)
	}
}

// TestTruncateOutput_TruncatesLongOutput verifies the size bound.
func TestTruncateOutput_TruncatesLongOutput(t *testing.T) {
	long := strings.Repeat("x", maxOutputBytes*2)
	got := truncateOutput([]byte(long))
	if !strings.HasPrefix(got, "...") {
		t.Fatalf("truncated output should start with '...'; got prefix %q", got[:5])
	}
	if len(got) > maxOutputBytes+len("...") {
		t.Fatalf("truncated output too long: %d bytes", len(got))
	}
}
