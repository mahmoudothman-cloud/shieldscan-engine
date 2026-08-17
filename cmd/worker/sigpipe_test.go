package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// These tests pin the fix for the container-leak root cause: the worker used
// to die of SIGPIPE the moment it logged its first shutdown line into a pipe
// whose reader (`tee`) had already exited, so WarmPool.Shutdown never ran.
//
// The behaviour cannot be asserted in-process — an unguarded SIGPIPE kills
// the test binary itself. Both tests therefore re-exec this test binary as a
// child with fd 1/2 wired to a pipe that has no reader, and check two
// independent things: the child's exit status, and whether a marker file
// written AFTER the doomed log line exists. The marker is what makes this a
// test of "cleanup ran" rather than "the process happened to survive".

const (
	childEnv       = "SHIELDSCAN_SIGPIPE_CHILD"
	childMarkerEnv = "SHIELDSCAN_SIGPIPE_MARKER"
)

// runChildWithClosedStdout re-execs this test binary with stdout+stderr on a
// pipe with no reader, and returns the child's error plus the marker path.
//
// No readiness handshake is needed: the read end is closed before Wait, and
// the child does not write until it starts its shutdown sequence, so the
// pipe is reliably broken by the time it matters.
func runChildWithClosedStdout(t *testing.T, mode string) (markerPath string, waitErr error) {
	t.Helper()

	markerPath = filepath.Join(t.TempDir(), "cleanup-ran")

	// CommandContext per ADR-021 Rule 1 — also a real backstop here: if a
	// regression made the child block instead of exiting, the timeout kills
	// it rather than hanging the suite.
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)

	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+t.Name()+"$")
	cmd.Env = append(os.Environ(),
		childEnv+"="+mode,
		childMarkerEnv+"="+markerPath,
	)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	cmd.Stdout = w
	cmd.Stderr = w

	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	// Drop both parent-side handles. Closing the read end is what makes the
	// child's fd 1/2 a pipe with no reader; closing our copy of the write end
	// makes the child the only writer.
	_ = w.Close()
	_ = r.Close()

	return markerPath, cmd.Wait()
}

// childShutdownSequence mimics run.go's shutdown ordering: log first, then do
// the cleanup that actually matters. If the log write is fatal, the cleanup
// below it never happens — which is precisely the production bug.
func childShutdownSequence() {
	if os.Getenv(childEnv) == "guard" {
		installSIGPIPEGuard()
	}

	// run.go:158 — the write that killed the worker.
	os.Stdout.WriteString("shutdown signal received; draining in-flight jobs\n") //nolint:errcheck
	os.Stderr.WriteString("draining\n")                                          //nolint:errcheck

	// The stand-in for WarmPool.Shutdown reaping containers.
	_ = os.WriteFile(os.Getenv(childMarkerEnv), []byte("cleanup ran\n"), 0o600)

	// Exit explicitly: the testing framework's own summary would be written
	// to the same broken pipe, and we want a deterministic status.
	os.Exit(0)
}

// signalOf returns the signal that killed the process, or 0 if it exited
// normally.
func signalOf(err error) syscall.Signal {
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return 0
	}
	status, ok := exitErr.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() {
		return 0
	}
	return status.Signal()
}

// TestSIGPIPEGuardLetsShutdownFinish is the assertion that matters: with the
// guard installed, a dead stdout reader does not stop the cleanup that runs
// after the log line.
func TestSIGPIPEGuardLetsShutdownFinish(t *testing.T) {
	if os.Getenv(childEnv) != "" {
		childShutdownSequence()
		return
	}

	marker, err := runChildWithClosedStdout(t, "guard")

	if sig := signalOf(err); sig != 0 {
		t.Fatalf("child was killed by %v; the guard should make writes to a "+
			"broken fd 1/2 return EPIPE instead of terminating the process", sig)
	}
	if err != nil {
		t.Fatalf("child exited non-zero: %v", err)
	}
	if _, statErr := os.Stat(marker); statErr != nil {
		t.Fatalf("cleanup marker missing (%v) — the process survived but the "+
			"work after the log write did not run", statErr)
	}
}

// TestSIGPIPEWithoutGuardIsFatal is the negative control. It documents the
// runtime behaviour the guard exists to defeat, and keeps the guard honest:
// without it the child dies of SIGPIPE and never reaches its cleanup.
//
// If this test ever fails because the child survives, Go's fd-1/2 SIGPIPE
// behaviour has changed and installSIGPIPEGuard should be re-evaluated
// rather than kept as ceremony.
func TestSIGPIPEWithoutGuardIsFatal(t *testing.T) {
	if os.Getenv(childEnv) != "" {
		childShutdownSequence()
		return
	}

	marker, err := runChildWithClosedStdout(t, "noguard")

	if sig := signalOf(err); sig != syscall.SIGPIPE {
		t.Fatalf("expected the unguarded child to be killed by SIGPIPE, got "+
			"err=%v signal=%v; if Go no longer terminates on a broken fd 1/2, "+
			"installSIGPIPEGuard is no longer needed", err, sig)
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("cleanup marker exists — the unguarded child reached cleanup, " +
			"so this control no longer demonstrates anything")
	}
}
