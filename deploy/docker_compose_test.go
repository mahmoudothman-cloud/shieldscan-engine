// Package deploy holds tests validating the operational artifacts
// shipped under deploy/.
package deploy

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// composeFile loads the docker-compose.services.yml relative to this
// test file's location (so tests work regardless of CWD).
func composeFile(t *testing.T) []byte {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	path := filepath.Join(filepath.Dir(thisFile), "docker-compose.services.yml")
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return data
}

// TestDockerCompose_YAMLParses pins the basic invariant: the file
// is valid YAML.
func TestDockerCompose_YAMLParses(t *testing.T) {
	data := composeFile(t)
	var parsed map[string]any
	require.NoError(t, yaml.Unmarshal(data, &parsed),
		"docker-compose.services.yml must be valid YAML")
	assert.NotNil(t, parsed["services"])
}

// TestDockerCompose_ExpectedServicesPresent pins the four M7
// services per TOOL-ARCHITECTURE.md §2.3.
func TestDockerCompose_ExpectedServicesPresent(t *testing.T) {
	data := composeFile(t)
	var parsed struct {
		Services map[string]any `yaml:"services"`
	}
	require.NoError(t, yaml.Unmarshal(data, &parsed))

	// "zap" removed per Task 7.3 Q3 lock + Task 7.5b V4 Option γ ephemeral
	// default; ZAP is now per-scan ephemeral via DockerServiceRunner.
	// "mobsf" removed per Task 7.4 Q3 lock + Q5 Option β v1 ephemeral
	// default; MobSF is now per-scan ephemeral via DockerServiceRunner.
	for _, svc := range []string{"trivy", "sqlmap"} {
		assert.Contains(t, parsed.Services, svc,
			"service %q must be defined per TOOL-ARCH §2.3", svc)
	}
}

// TestDockerCompose_ImagesMatchVERSIONS pins the cross-doc contract:
// image tags MUST match VERSIONS.md §2.5 exactly. The test reads the
// raw YAML and grep-checks for each pinned tag — drift between
// VERSIONS.md and this file is the test's purpose to surface.
//
// If a VERSIONS.md update changes a pinned tag, this test fails
// until docker-compose.services.yml is updated to match. That's
// the cross-doc forcing function.
func TestDockerCompose_ImagesMatchVERSIONS(t *testing.T) {
	raw := string(composeFile(t))

	// Pinned image tags from VERSIONS.md §2.5 (see ../shieldscan-docs/).
	// "zap" removed per Task 7.3 Q3 lock; ZAP digest pinned in
	// internal/tools/docker/service/zap (consumer-side) instead.
	// "mobsf" removed per Task 7.4 Q3 lock; MobSF digest pinned in
	// internal/tools/docker/service/mobsf (consumer-side) instead.
	expectedImages := map[string]string{
		"trivy":  "aquasec/trivy:0.58.0",
		"sqlmap": "paoloo/sqlmap:1.9",
	}

	for svc, image := range expectedImages {
		assert.Contains(t, raw, image,
			"%s image must match VERSIONS.md §2.5 pin: %s", svc, image)
	}
}

// TestDockerCompose_HealthChecksDefined pins the operational
// contract: every service has a healthcheck stanza so worker
// startup Phase 2 health verification has something to call.
//
// Without healthchecks, M7 task DockerServiceRunner.HealthCheck
// can still call its configured HealthPath, but Docker-level
// health (visible via `docker ps` and orchestration platforms)
// would be missing.
func TestDockerCompose_HealthChecksDefined(t *testing.T) {
	data := composeFile(t)
	var parsed struct {
		Services map[string]struct {
			Image       string `yaml:"image"`
			Healthcheck *struct {
				Test []string `yaml:"test"`
			} `yaml:"healthcheck"`
		} `yaml:"services"`
	}
	require.NoError(t, yaml.Unmarshal(data, &parsed))

	for name, svc := range parsed.Services {
		require.NotNil(t, svc.Healthcheck,
			"service %q must define healthcheck", name)
		assert.NotEmpty(t, svc.Healthcheck.Test,
			"service %q healthcheck.test must be non-empty", name)
	}
}

// TestDockerCompose_RawDoesNotContainSecrets is a defensive check.
// The compose file accepts secrets via env interpolation. Verify
// no literal secret-looking strings shipped.
func TestDockerCompose_RawDoesNotContainSecrets(t *testing.T) {
	raw := string(composeFile(t))
	// Heuristic patterns; not exhaustive.
	suspicious := []string{
		"password=",
		"secret=",
		"api_key=",
		"token=",
	}
	lower := strings.ToLower(raw)
	for _, pat := range suspicious {
		assert.NotContains(t, lower, pat,
			"docker-compose.services.yml should not contain literal %q; use env interpolation", pat)
	}
}
