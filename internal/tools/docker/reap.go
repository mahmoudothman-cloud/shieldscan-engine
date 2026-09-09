package docker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/rs/zerolog"
)

// Orphan reaping — the safety net under WarmPool.Shutdown.
//
// Shutdown is the happy path: it drains the pool and removes each warmed
// container. Three cases route around it entirely, and no amount of care in
// the shutdown path can cover them:
//
//   - SIGKILL, or a panic — no deferred code runs at all.
//   - A kill while a container is checked out. Shutdown deliberately does NOT
//     stop in-use containers (see its docstring), so a worker killed mid-scan
//     leaks the container it was scanning with even on the graceful path.
//   - Any signal the worker does not handle (it registers only SIGINT and
//     SIGTERM; a SIGHUP from `tmux kill-session` is immediately fatal).
//
// So containers are labelled at create and orphans are reaped at startup.
// Reaping keys on OUR label, never on the image: an `ancestor=` filter would
// also match a container an operator started by hand from the same image.

const (
	// LabelManaged marks a container as created by a ShieldScan warm pool.
	// Presence of this label is the ONLY thing that makes a container
	// eligible for reaping.
	LabelManaged = "io.shieldscan.managed"

	// LabelWorkerID records the id of the worker process that created the
	// container. Reaping compares this against the live set.
	LabelWorkerID = "io.shieldscan.worker-id"

	// LabelPool records which warm pool owns the container (e.g. "nmap"),
	// for operator legibility — `docker ps --filter label=io.shieldscan.pool=nmap`.
	LabelPool = "io.shieldscan.pool"

	managedValue = "true"
)

// PoolLabels builds the label set stamped on every container a pool creates.
func PoolLabels(workerID, pool string) map[string]string {
	return map[string]string{
		LabelManaged:  managedValue,
		LabelWorkerID: workerID,
		LabelPool:     pool,
	}
}

// ContainerLister is the narrow Docker capability the reaper needs.
//
// Deliberately NOT folded into dockerClient: that interface is implemented by
// six test stubs across four packages, and widening it would force each to
// grow a method it never calls. *client.Client satisfies this naturally.
type ContainerLister interface {
	ContainerList(ctx context.Context, options container.ListOptions) ([]container.Summary, error)
	ContainerRemove(ctx context.Context, containerID string, options container.RemoveOptions) error
}

// ContainerLogReader is the narrow Docker capability needed to read a
// container's output before removing it.
//
// Same shape and same reasoning as ContainerLister above: folding
// ContainerLogs into dockerClient would force six test stubs across four
// packages to grow a method almost none of them exercise. *client.Client
// satisfies this naturally, and productionClient is asserted against it
// below so the production path can never silently lose the capability.
type ContainerLogReader interface {
	ContainerLogs(ctx context.Context, containerID string, options container.LogsOptions) (io.ReadCloser, error)
}

// CaptureLogs returns up to maxBytes of a container's combined
// stdout+stderr, for the diagnosis of a container that is about to be
// destroyed.
//
// It exists because the readiness path used to stop and remove a
// container the instant it failed to come up, taking the logs, the exit
// code and the OOMKilled flag with it. ZAP's readiness failed three
// times over two months and each occurrence left literally nothing to
// read; the container's own output was deleted by the error handler
// reporting that something was wrong with it.
//
// Best-effort by construction: every failure returns a string describing
// why there are no logs rather than an error, because the caller is
// already handling a more important one and must not be derailed by
// this. A cli that does not implement ContainerLogReader (test stubs)
// yields a short note saying so.
//
// Docker multiplexes stdout and stderr into a single framed stream for
// non-TTY containers, so the payload is demultiplexed via stdcopy;
// both streams are interleaved into the result because for a failed
// boot the ordering between them is the useful part.
func CaptureLogs(ctx context.Context, cli DockerClient, containerID string, maxBytes int) string {
	reader, ok := cli.(ContainerLogReader)
	if !ok {
		return "(logs unavailable: docker client does not support log reading)"
	}
	rc, err := reader.ContainerLogs(ctx, containerID, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Tail:       "all",
	})
	if err != nil {
		return fmt.Sprintf("(logs unavailable: %v)", err)
	}
	defer func() { _ = rc.Close() }()

	var out, errOut bytes.Buffer
	if _, copyErr := stdcopy.StdCopy(&out, &errOut, rc); copyErr != nil && !errors.Is(copyErr, io.EOF) {
		// Keep whatever was demultiplexed before the error; a partial log
		// is the whole point of this function.
		fmt.Fprintf(&out, "\n(log stream error: %v)", copyErr)
	}
	out.Write(errOut.Bytes())

	if out.Len() == 0 {
		return "(container produced no output)"
	}
	// Keep the TAIL: a container that dies during boot says why at the end.
	b := out.Bytes()
	if maxBytes > 0 && len(b) > maxBytes {
		return "...(truncated)...\n" + string(b[len(b)-maxBytes:])
	}
	return string(b)
}

// DescribeState renders a container's terminal state for an error
// message: whether it is running, how it exited, and whether the kernel
// killed it. Returns "" when the state cannot be determined, so callers
// can append it conditionally.
//
// Note the double nil check. InspectResponse embeds *ContainerJSONBase
// as a POINTER, so reading insp.State panics outright when the base is
// absent — which is the shape any hand-built InspectResponse has,
// including every test fixture in this repo. A real daemon always
// populates it; a nil-base response is the case that would have turned
// a diagnostic into a worker crash.
func DescribeState(insp container.InspectResponse) string {
	if insp.ContainerJSONBase == nil || insp.State == nil {
		return ""
	}
	s := insp.State
	desc := fmt.Sprintf("status=%s exit_code=%d", s.Status, s.ExitCode)
	if s.OOMKilled {
		desc += " oom_killed=true"
	}
	if s.Error != "" {
		desc += " error=" + s.Error
	}
	return desc
}

// ReapPolicy decides which managed containers are orphans.
//
// LiveWorkerIDs is the crux. Reaping "anything not mine" is wrong the moment a
// second worker shares a host: it would delete the containers of a healthy
// peer mid-scan. The caller supplies the set of workers currently
// heartbeating, and only containers belonging to neither this worker nor a
// live one are removed.
//
// A nil LiveWorkerIDs means "liveness unknown" and disables reaping entirely
// (see ReapOrphans). Fail-safe: leaking a few hundred KiB of idle container is
// vastly cheaper than killing a running peer's scan.
type ReapPolicy struct {
	SelfWorkerID  string
	LiveWorkerIDs map[string]struct{}
}

// ReapOrphans removes managed containers left behind by workers that are gone.
//
// Returns the number removed. Errors on individual removals are logged and
// counted but do not abort the sweep — one undeletable container must not stop
// the rest from being cleaned up. A listing failure IS returned, since it
// means we know nothing.
//
// Callers treat any error as non-fatal to startup: failing to reap is untidy,
// failing to boot is an outage.
func ReapOrphans(ctx context.Context, cli ContainerLister, policy ReapPolicy, log zerolog.Logger) (int, error) {
	if policy.LiveWorkerIDs == nil {
		log.Warn().Msg("orphan reap skipped: live-worker set unavailable; " +
			"cannot distinguish a dead worker's containers from a live peer's")
		return 0, nil
	}

	// All=true so containers that are stopped-but-not-removed are reaped too
	// (a half-finished Stop leaves exactly that).
	summaries, err := cli.ContainerList(ctx, container.ListOptions{
		All:     true,
		Filters: filters.NewArgs(filters.Arg("label", LabelManaged+"="+managedValue)),
	})
	if err != nil {
		return 0, fmt.Errorf("docker: list managed containers: %w", err)
	}

	removed := 0
	for _, s := range summaries {
		owner := s.Labels[LabelWorkerID]
		if owner == policy.SelfWorkerID {
			continue // ours — we are still starting up, so this is a leftover of
			// a previous process only if ids collide, which they do not.
		}
		if _, alive := policy.LiveWorkerIDs[owner]; alive {
			continue // a healthy peer is using it
		}

		if err := cli.ContainerRemove(ctx, s.ID, container.RemoveOptions{Force: true}); err != nil {
			log.Warn().Err(err).
				Str("container_id", shortID(s.ID)).
				Str("owner_worker_id", owner).
				Msg("orphan container remove failed; continuing sweep")
			continue
		}
		removed++
		log.Info().
			Str("container_id", shortID(s.ID)).
			Str("owner_worker_id", owner).
			Str("pool", s.Labels[LabelPool]).
			Msg("reaped orphan container from dead worker")
	}

	return removed, nil
}
