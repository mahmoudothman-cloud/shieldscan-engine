package docker

import (
	"context"
	"fmt"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
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
