package worker

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/odyssey/shieldscan-engine/internal/events"
	"github.com/odyssey/shieldscan-engine/internal/tools"
)

// stubRunner is a minimal ToolRunner for registry tests. The fuller
// testRunner type with concurrency tracking lives in processor_test.go.
type stubRunner struct {
	name     string
	category string
}

func (s *stubRunner) Name() string     { return s.name }
func (s *stubRunner) Category() string { return s.category }
func (s *stubRunner) Run(_ context.Context, _ tools.Target, _ tools.ScanConfig) ([]events.RawFinding, error) {
	return nil, nil
}

var _ tools.ToolRunner = (*stubRunner)(nil)

// TestRegistry_GetReturnsRunner pins the canonical happy path.
func TestRegistry_GetReturnsRunner(t *testing.T) {
	nuc := &stubRunner{name: "nuclei", category: "dast"}
	sem := &stubRunner{name: "semgrep", category: "sast"}
	r := NewRegistry(map[string]tools.ToolRunner{
		"nuclei":  nuc,
		"semgrep": sem,
	})

	got, err := r.Get("nuclei")
	require.NoError(t, err)
	assert.Equal(t, "nuclei", got.Name())
	assert.Same(t, nuc, got, "Get returns the registered instance")

	got, err = r.Get("semgrep")
	require.NoError(t, err)
	assert.Equal(t, "semgrep", got.Name())
}

// TestRegistry_GetUnknownErrors pins the H.4 contract: unregistered
// engine returns an error so the processor can emit job_failed.
func TestRegistry_GetUnknownErrors(t *testing.T) {
	r := NewRegistry(map[string]tools.ToolRunner{})

	_, err := r.Get("nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no runner registered")
	assert.Contains(t, err.Error(), "nonexistent")
}

// TestRegistry_FrozenAtConstruction pins the defensive-copy contract:
// mutating the input map after NewRegistry does NOT affect the
// registry. Without this guarantee, M5.6 startup population would
// need explicit synchronization.
func TestRegistry_FrozenAtConstruction(t *testing.T) {
	input := map[string]tools.ToolRunner{
		"nuclei": &stubRunner{name: "nuclei", category: "dast"},
	}
	r := NewRegistry(input)

	// Mutate the input map after construction.
	input["nuclei"] = &stubRunner{name: "imposter", category: "evil"}
	input["new_tool"] = &stubRunner{name: "new_tool", category: "x"}

	// Registry is unaffected.
	got, err := r.Get("nuclei")
	require.NoError(t, err)
	assert.Equal(t, "nuclei", got.Name(),
		"Registry holds defensive copy; input mutation has no effect")

	_, err = r.Get("new_tool")
	require.Error(t, err, "post-construction additions to input map invisible to registry")

	// Engines() reflects only constructor-time entries.
	engines := r.Engines()
	assert.Equal(t, []string{"nuclei"}, engines)
}
