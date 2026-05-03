// Package jsonx tests pin the lenient-decode helpers' behavior at
// the type-assertion boundaries: nil map, missing key, type mismatch,
// and the array-or-bare-string tolerance. These are the patterns
// every M6 tool parser depends on.
package jsonx

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// ─── ExtractString ───────────────────────────────────────────────────

func TestExtractString(t *testing.T) {
	type tc struct {
		name string
		m    map[string]any
		key  string
		want string
	}
	cases := []tc{
		{"happy", map[string]any{"k": "v"}, "k", "v"},
		{"missing-key", map[string]any{"other": "x"}, "k", ""},
		{"nil-map", nil, "k", ""},
		{"wrong-type-int", map[string]any{"k": 42}, "k", ""},
		{"wrong-type-bool", map[string]any{"k": true}, "k", ""},
		{"wrong-type-array", map[string]any{"k": []any{"x"}}, "k", ""},
		{"empty-string-passes", map[string]any{"k": ""}, "k", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, ExtractString(c.m, c.key))
		})
	}
}

// TestExtractString_NestedNotSupported is a regression guard
// documenting that this helper does NOT walk dotted paths. Callers
// compose via ExtractMap chaining instead.
func TestExtractString_NestedNotSupported(t *testing.T) {
	m := map[string]any{
		"a": map[string]any{"b": "nested"},
	}
	// "a.b" is treated as a literal key — no walking.
	assert.Equal(t, "", ExtractString(m, "a.b"))
	// Composition: ExtractString(ExtractMap(m, "a"), "b") works.
	assert.Equal(t, "nested", ExtractString(ExtractMap(m, "a"), "b"))
}

// ─── ExtractMap ──────────────────────────────────────────────────────

func TestExtractMap(t *testing.T) {
	type tc struct {
		name string
		m    map[string]any
		key  string
		want map[string]any
	}
	cases := []tc{
		{"happy", map[string]any{"k": map[string]any{"x": 1}},
			"k", map[string]any{"x": 1}},
		{"missing-key", map[string]any{}, "k", nil},
		{"nil-map", nil, "k", nil},
		{"wrong-type-string", map[string]any{"k": "not-a-map"}, "k", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, ExtractMap(c.m, c.key))
		})
	}
}

// ─── ExtractStringSlice ──────────────────────────────────────────────

func TestExtractStringSlice(t *testing.T) {
	type tc struct {
		name string
		m    map[string]any
		key  string
		want []string
	}
	cases := []tc{
		{"happy-array",
			map[string]any{"k": []any{"a", "b", "c"}}, "k",
			[]string{"a", "b", "c"}},
		{"missing-key", map[string]any{}, "k", nil},
		{"nil-map", nil, "k", nil},
		{"wrong-type-int", map[string]any{"k": 42}, "k", nil},
		{"mixed-array-filters-non-strings",
			map[string]any{"k": []any{"a", 42, "b", true, "c"}}, "k",
			[]string{"a", "b", "c"}},
		{"empty-array",
			map[string]any{"k": []any{}}, "k",
			[]string{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, ExtractStringSlice(c.m, c.key))
		})
	}
}

// TestExtractStringSlice_TolerantOfBareString pins the Nuclei-pre-v3
// quirk: a bare string where an array is expected is wrapped to a
// single-element slice. Regression guard: don't tighten this without
// auditing all callsites.
func TestExtractStringSlice_TolerantOfBareString(t *testing.T) {
	m := map[string]any{"k": "alone"}
	assert.Equal(t, []string{"alone"}, ExtractStringSlice(m, "k"))
}

// ─── ExtractFloat ────────────────────────────────────────────────────

func TestExtractFloat(t *testing.T) {
	type tc struct {
		name string
		m    map[string]any
		key  string
		want float64
	}
	cases := []tc{
		{"happy", map[string]any{"k": 3.14}, "k", 3.14},
		{"happy-zero", map[string]any{"k": 0.0}, "k", 0.0},
		{"missing-key", map[string]any{}, "k", 0},
		{"nil-map", nil, "k", 0},
		{"wrong-type-string", map[string]any{"k": "3.14"}, "k", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.InDelta(t, c.want, ExtractFloat(c.m, c.key), 0.0001)
		})
	}
}

// TestExtractFloat_JSONNumberAsFloat64 pins the contract this helper
// relies on: stdlib `json.Unmarshal` into `any` decodes JSON numbers
// as float64. If a future Go release changes that decode (or callers
// switch to json.Decoder with UseNumber), this test surfaces the
// breakage.
func TestExtractFloat_JSONNumberAsFloat64(t *testing.T) {
	// Simulate the post-Unmarshal shape: numbers are float64, even
	// integral ones.
	m := map[string]any{
		"int_as_float":                 float64(42),
		"frac":                         0.5,
		"large":                        float64(1234567890),
		"would-be-int-typed-elsewhere": 7.0,
	}
	assert.InDelta(t, 42.0, ExtractFloat(m, "int_as_float"), 0.0001)
	assert.InDelta(t, 0.5, ExtractFloat(m, "frac"), 0.0001)
	assert.InDelta(t, 1234567890.0, ExtractFloat(m, "large"), 0.0001)
	assert.InDelta(t, 7.0, ExtractFloat(m, "would-be-int-typed-elsewhere"), 0.0001)
}

// ─── FirstString ─────────────────────────────────────────────────────

func TestFirstString(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want string
	}{
		{"happy", []string{"a", "b"}, "a"},
		{"single", []string{"only"}, "only"},
		{"empty", []string{}, ""},
		{"nil", nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, FirstString(c.in))
		})
	}
}

// ─── Truncate ────────────────────────────────────────────────────────

func TestTruncate(t *testing.T) {
	cases := []struct {
		name string
		s    string
		n    int
		want string
	}{
		{"under-cap", "abc", 5, "abc"},
		{"exactly-cap", "abcde", 5, "abcde"},
		{"over-cap-suffix-appended", "abcdefgh", 5, "abcde..."},
		{"empty", "", 5, ""},
		{"zero-cap", "abc", 0, "..."},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, Truncate(c.s, c.n))
		})
	}
}

func TestFilterEngineCategoryTags(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil-input", nil, nil},
		{"empty-input", []string{}, nil},
		{"all-tags-survive", []string{"xss", "owasp-top-10", "automated"}, []string{"xss", "owasp-top-10", "automated"}},
		{"drops-engine-category-dast", []string{"dast", "xss"}, []string{"xss"}},
		{"drops-multiple-categories", []string{"dast", "sast", "xss", "automated"}, []string{"xss", "automated"}},
		{"all-categories-filtered-to-nil", []string{"dast", "ssl"}, nil},
		{"preserves-order", []string{"a", "dast", "b", "sast", "c"}, []string{"a", "b", "c"}},
		{"case-sensitive-DAST-uppercase-survives", []string{"DAST", "xss"}, []string{"DAST", "xss"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, FilterEngineCategoryTags(c.in))
		})
	}
}
