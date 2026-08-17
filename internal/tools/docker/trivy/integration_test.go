//go:build integration
// +build integration

// Package trivy integration tests — run with `go test -tags integration`.
//
// CONVENTION NOTE: This is the FIRST build-tag integration test in the
// shieldscan-engine codebase. No prior precedent — Nmap unit tests use
// stubbed Docker clients (testhelpers_test.go) and never exec real
// containers. The build-tag isolation pattern is standard-Go convention
// for slow/external-dependency tests; landing it here establishes
// precedent for future DockerRunner consumers (SQLMap Task 7.6).
//
// Default `go test ./...` SKIPS this file (build constraint excludes it).
// Real-container tests run only when `-tags integration` is passed
// explicitly (CI integration job + local empirical verification).
//
// FRAMEWORK GAP — Phase 1 P1.8 finding (D-PLAN candidate):
// DefaultContainerFactory at internal/tools/docker/container.go creates
// warm-pool containers with NO Mounts, NO Docker socket access, NO host
// bind-mounts. Trivy integration scans require EITHER:
//
//   - image-mode: Docker socket mount (so Trivy inside the container
//     can pull `alpine:3.10` from the host's daemon); OR registry
//     network reachability + image pre-pull within the Trivy container.
//   - fs-mode: host bind-mount of the scan target directory (so
//     /tmp/trivy-fs-test/ host path is reachable as e.g. /scan inside
//     the Trivy container).
//
// Neither capability exists in the current framework. Per ADR-026 line
// 2093 anticipated framework-gap escape hatch: this is a legitimate
// additive framework change candidate. Resolution paths:
//
//   (α) Extend DockerRunner.Config OR add per-consumer ContainerFactory
//       override accepting Mounts + HostConfig customization (Task 7.5b
//       ContainerFactory hook is the natural extension point).
//   (β) Add Trivy-specific ContainerFactory override in trivy.NewPool
//       that mounts /var/run/docker.sock and accepts a host-path-mount
//       parameter for fs-mode scan targets.
//   (γ) Defer to a v1.1+ framework task; integration tests stay in
//       this file marked t.Skip with rationale.
//
// Current commit chooses (γ): tests defined but t.Skip on framework
// gap. When framework extension lands, remove t.Skip + tests become
// empirical verification of full end-to-end path.
package trivy

import (
	"context"
	"strings"
	"testing"
	"time"

	dockerclient "github.com/docker/docker/client"
	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newIntegrationPool spins up a real Trivy WarmPool against the local
// Docker daemon. Caller is responsible for ensuring aquasec/trivy:0.70.0
// is cached (per Phase 0 v2 acquisition; image pre-pulled at session
// setup).
func newIntegrationPool(t *testing.T) (*tools.Target, func()) {
	t.Helper()
	_, err := dockerclient.NewClientWithOpts(
		dockerclient.FromEnv,
		dockerclient.WithAPIVersionNegotiation(),
	)
	require.NoError(t, err, "docker daemon must be reachable for integration tests")
	return &tools.Target{}, func() {}
}

// TestIntegration_TrivyContainer_Alpine exercises image-mode scan
// end-to-end through the Q2 dual-registration TrivyContainerScanner.
// Expected against alpine:3.10 (Phase 0 v2 baseline): 1 finding
// (CVE-2021-36159 CRITICAL apk-tools).
//
// Task 7.5e Phase 0 v2 V1.s-ii: image-mode scan requires NO framework
// mounts (OCI registry pull works without Docker socket). t.Skip
// lifted in Task 7.5e Phase 2 — no framework dependency beyond network
// reachability inside the warm-pool container.
func TestIntegration_TrivyContainer_Alpine(t *testing.T) {
	_, cleanup := newIntegrationPool(t)
	defer cleanup()

	cli, err := dockerclient.NewClientWithOpts(
		dockerclient.FromEnv,
		dockerclient.WithAPIVersionNegotiation(),
	)
	require.NoError(t, err)
	pool, err := NewPool(cli, "test-worker", zerolog.Nop())
	require.NoError(t, err)
	defer func() { _ = pool.Shutdown(context.Background()) }()

	runner := NewContainerRunner(pool, zerolog.Nop())
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	findings, err := runner.Run(ctx, tools.Target{URL: "alpine:3.10", TargetType: "container"}, tools.ScanConfig{})
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(findings), 1, "alpine:3.10 baseline expects at least 1 finding (CVE-2021-36159)")

	// Verify CVE-2021-36159 present
	found := false
	for _, f := range findings {
		if strings.Contains(f.Metadata["vulnerability_id"], "CVE-2021-36159") {
			found = true
			assert.Equal(t, "apk-tools", f.ComponentName, "Q6 typed-field reuse")
			assert.Equal(t, "critical", f.Severity, "Trivy CRITICAL → ShieldScan critical")
			break
		}
	}
	assert.True(t, found, "CVE-2021-36159 (Phase 0 v2 alpine:3.10 baseline) must be present in findings")
}

// TestIntegration_TrivyFs_TestData exercises fs-mode scan end-to-end
// through TrivyFsScanner against the Phase 0 v2 multi-manifest fixture
// directory (/tmp/trivy-fs-test/; 3 lockfiles; 57-finding baseline).
//
// Task 7.5e Phase 0 v2 V2 + Phase 2 P2.1: framework Mounts capability
// + Trivy NewPool bind-mount land enable this test. Host bind-mount
// source = TRIVY_SCAN_BASE_PATH env (defaults to /tmp); container
// target = /scan; ReadOnly:true per V4 empirical lock. Fixture at
// /tmp/trivy-fs-test/ becomes /scan/trivy-fs-test/ inside the
// container per (α) lean (explicit container path; no framework
// path-translation).
func TestIntegration_TrivyFs_TestData(t *testing.T) {
	cli, err := dockerclient.NewClientWithOpts(
		dockerclient.FromEnv,
		dockerclient.WithAPIVersionNegotiation(),
	)
	require.NoError(t, err)
	pool, err := NewPool(cli, "test-worker", zerolog.Nop())
	require.NoError(t, err)
	defer func() { _ = pool.Shutdown(context.Background()) }()

	runner := NewFsRunner(pool, zerolog.Nop())
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	findings, err := runner.Run(ctx, tools.Target{SourcePath: "/scan/trivy-fs-test", TargetType: "source"}, tools.ScanConfig{})
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(findings), 50, "fs-mode baseline expects at least 50 findings (Phase 0 v2: 57)")

	// Verify multi-manifest Class/Type distribution per Phase 0 v2
	typeDistribution := map[string]int{}
	for _, f := range findings {
		typeDistribution[f.Metadata["type"]]++
		assert.Equal(t, "lang-pkgs", f.Metadata["class"], "fs-mode uniformly lang-pkgs Class")
	}
	assert.Contains(t, typeDistribution, "bundler")
	assert.Contains(t, typeDistribution, "npm")
	assert.Contains(t, typeDistribution, "pip")
}

// TestIntegration_TrivyContainer_RegistrationShape is a non-Skip
// integration smoke verifying the constructors instantiate against a
// real Docker daemon (no actual scan). Validates V7 trivially-clean
// two-ToolRunner registration empirically — both runners share the
// same pool; both register distinct Names; framework wiring sound.
//
// This test DOES run under -tags integration because it only exercises
// NewPool + NewContainerRunner + NewFsRunner constructors (no
// container.Exec; no framework-gap path).
func TestIntegration_TrivyContainer_RegistrationShape(t *testing.T) {
	cli, err := dockerclient.NewClientWithOpts(
		dockerclient.FromEnv,
		dockerclient.WithAPIVersionNegotiation(),
	)
	require.NoError(t, err)

	pool, err := NewPool(cli, "test-worker", zerolog.Nop())
	require.NoError(t, err)
	require.NotNil(t, pool)
	defer func() { _ = pool.Shutdown(context.Background()) }()

	containerRunner := NewContainerRunner(pool, zerolog.Nop())
	fsRunner := NewFsRunner(pool, zerolog.Nop())

	assert.Equal(t, "trivy-container", containerRunner.Name())
	assert.Equal(t, "container", containerRunner.Category())
	assert.Equal(t, "trivy-fs", fsRunner.Name())
	assert.Equal(t, "sca", fsRunner.Category())
	assert.Same(t, containerRunner.Pool, fsRunner.Pool, "Q2 lock: single shared pool drives both runners")
}
