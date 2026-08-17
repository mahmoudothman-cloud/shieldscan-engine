package docker

import (
	"context"
	"errors"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/rs/zerolog"
)

// fakeLister is a stand-in for the narrow ContainerLister surface. Kept
// separate from the dockerClient stubs in testhelpers_test.go — the reaper
// deliberately does not use that interface.
type fakeLister struct {
	listed    []container.Summary
	listErr   error
	removed   []string
	removeErr map[string]error
	lastOpts  container.ListOptions
}

func (f *fakeLister) ContainerList(_ context.Context, opts container.ListOptions) ([]container.Summary, error) {
	f.lastOpts = opts
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.listed, nil
}

func (f *fakeLister) ContainerRemove(_ context.Context, id string, _ container.RemoveOptions) error {
	if err := f.removeErr[id]; err != nil {
		return err
	}
	f.removed = append(f.removed, id)
	return nil
}

func managed(id, workerID, pool string) container.Summary {
	return container.Summary{
		ID:     id,
		Labels: PoolLabels(workerID, pool),
	}
}

func liveSet(ids ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		m[id] = struct{}{}
	}
	return m
}

// The central case: a dead worker's containers go, a live peer's stay, and
// our own stay. Asserted together because the danger is not "does it delete"
// but "does it delete the wrong one".
func TestReapOrphansRemovesOnlyDeadWorkersContainers(t *testing.T) {
	f := &fakeLister{listed: []container.Summary{
		managed("dead-1", "worker-gone", "nmap"),
		managed("live-1", "worker-peer", "nmap"),
		managed("self-1", "worker-self", "trivy"),
		managed("dead-2", "worker-also-gone", "sqlmap"),
	}}

	n, err := ReapOrphans(context.Background(), f, ReapPolicy{
		SelfWorkerID:  "worker-self",
		LiveWorkerIDs: liveSet("worker-self", "worker-peer"),
	}, zerolog.Nop())
	if err != nil {
		t.Fatalf("ReapOrphans: %v", err)
	}

	if n != 2 {
		t.Errorf("removed count = %d, want 2", n)
	}
	got := map[string]bool{}
	for _, id := range f.removed {
		got[id] = true
	}
	if !got["dead-1"] || !got["dead-2"] {
		t.Errorf("dead workers' containers not reaped: removed=%v", f.removed)
	}
	if got["live-1"] {
		t.Error("reaped a LIVE peer worker's container — this would kill a running scan")
	}
	if got["self-1"] {
		t.Error("reaped our own container")
	}
}

// Fail-safe. A nil live set means liveness is unknown, and deleting on a
// guess could take out a healthy peer mid-scan.
func TestReapOrphansDeclinesWhenLivenessUnknown(t *testing.T) {
	f := &fakeLister{listed: []container.Summary{
		managed("dead-1", "worker-gone", "nmap"),
	}}

	n, err := ReapOrphans(context.Background(), f, ReapPolicy{
		SelfWorkerID:  "worker-self",
		LiveWorkerIDs: nil,
	}, zerolog.Nop())
	if err != nil {
		t.Fatalf("ReapOrphans: %v", err)
	}
	if n != 0 || len(f.removed) > 0 {
		t.Errorf("reaped with an unknown live set: n=%d removed=%v", n, f.removed)
	}
}

// The filter is the reason a human's `docker run instrumentisto/nmap` is
// never touched: eligibility comes from OUR label, not from the image.
func TestReapOrphansFiltersOnTheManagedLabel(t *testing.T) {
	f := &fakeLister{}
	if _, err := ReapOrphans(context.Background(), f, ReapPolicy{
		SelfWorkerID:  "worker-self",
		LiveWorkerIDs: liveSet("worker-self"),
	}, zerolog.Nop()); err != nil {
		t.Fatalf("ReapOrphans: %v", err)
	}

	if !f.lastOpts.All {
		t.Error("List did not set All; stopped-but-present containers would be missed")
	}
	want := LabelManaged + "=" + managedValue
	if !f.lastOpts.Filters.Match("label", want) {
		t.Errorf("list filter does not constrain to %q; an unlabelled container "+
			"from the same image could be reaped", want)
	}
}

// One undeletable container must not strand the others.
func TestReapOrphansContinuesAfterRemoveFailure(t *testing.T) {
	f := &fakeLister{
		listed: []container.Summary{
			managed("stubborn", "worker-gone", "nmap"),
			managed("dead-2", "worker-gone", "nmap"),
		},
		removeErr: map[string]error{"stubborn": errors.New("device or resource busy")},
	}

	n, err := ReapOrphans(context.Background(), f, ReapPolicy{
		SelfWorkerID:  "worker-self",
		LiveWorkerIDs: liveSet("worker-self"),
	}, zerolog.Nop())
	if err != nil {
		t.Fatalf("ReapOrphans returned error for a per-container failure: %v", err)
	}
	if n != 1 {
		t.Errorf("removed count = %d, want 1 (the one that succeeded)", n)
	}
	if len(f.removed) != 1 || f.removed[0] != "dead-2" {
		t.Errorf("sweep did not continue past the failure: removed=%v", f.removed)
	}
}

// A listing failure is different: we know nothing, so say so.
func TestReapOrphansReturnsListingErrors(t *testing.T) {
	f := &fakeLister{listErr: errors.New("daemon unreachable")}
	if _, err := ReapOrphans(context.Background(), f, ReapPolicy{
		SelfWorkerID:  "worker-self",
		LiveWorkerIDs: liveSet("worker-self"),
	}, zerolog.Nop()); err == nil {
		t.Fatal("expected an error when the container listing fails")
	}
}

// The reaper is only as good as the stamping. If Config.Labels stops
// reaching ContainerCreate, ReapOrphans still passes its own tests while
// silently matching nothing in production — so pin the plumbing end to end.
func TestWarmPoolStampsLabelsOntoCreatedContainers(t *testing.T) {
	fc := &fakeClient{createResp: container.CreateResponse{ID: "c1"}}

	pool, err := New(Config{
		Image:   "instrumentisto/nmap:7.94",
		MaxSize: 1,
		Cleanup: NoCleanup,
		Labels:  PoolLabels("worker-abc", "nmap"),
	}, fc, zerolog.Nop())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := pool.Checkout(context.Background()); err != nil {
		t.Fatalf("Checkout: %v", err)
	}

	if fc.lastConfig == nil {
		t.Fatal("ContainerCreate never received a Config")
	}
	got := fc.lastConfig.Labels
	for k, want := range PoolLabels("worker-abc", "nmap") {
		if got[k] != want {
			t.Errorf("label %s = %q, want %q — containers created without this "+
				"label are invisible to ReapOrphans", k, got[k], want)
		}
	}
}

// Pools that declare Mounts must still get Labels. This is the case the old
// three-branch factory tree would have broken: non-empty Mounts took a
// different path from the default one.
func TestWarmPoolStampsLabelsAlongsideMounts(t *testing.T) {
	fc := &fakeClient{createResp: container.CreateResponse{ID: "c1"}}

	pool, err := New(Config{
		Image:   "aquasec/trivy:latest",
		MaxSize: 1,
		Cleanup: NoCleanup,
		Mounts:  []mount.Mount{{Type: mount.TypeBind, Source: "/tmp", Target: "/scan", ReadOnly: true}},
		Labels:  PoolLabels("worker-abc", "trivy"),
	}, fc, zerolog.Nop())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := pool.Checkout(context.Background()); err != nil {
		t.Fatalf("Checkout: %v", err)
	}

	if fc.lastConfig == nil || fc.lastConfig.Labels[LabelWorkerID] != "worker-abc" {
		t.Errorf("mounted pool lost its labels: %v", fc.lastConfig)
	}
	if fc.lastHostConfig == nil || len(fc.lastHostConfig.Mounts) != 1 {
		t.Errorf("mounted pool lost its mounts: %v", fc.lastHostConfig)
	}
}
