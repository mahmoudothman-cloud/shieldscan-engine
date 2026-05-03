// Package recon tests for the Subfinder JSONL parser. Per ADR-022,
// recon is helpers (not ToolRunner-registered); these tests cover
// the parser surface only — orchestration tests live in
// recon_test.go.
package recon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fixturePath(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("testdata", name)
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(fixturePath(t, name))
	require.NoError(t, err)
	return data
}

// ─── parseSubfinderOutput (5) ────────────────────────────────────────

func TestParseSubfinderOutput_Basic(t *testing.T) {
	subs := parseSubfinderOutput(readFixture(t, "subfinder_basic.jsonl"))
	require.Len(t, subs, 1)
	assert.Equal(t, "api.example.com", subs[0])
}

func TestParseSubfinderOutput_Multi(t *testing.T) {
	subs := parseSubfinderOutput(readFixture(t, "subfinder_multi.jsonl"))
	require.Len(t, subs, 8, "fixture has 8 subdomains across 3 sources")

	// Verify expected subdomains are all present (order-independent).
	want := []string{
		"api.example.com", "www.example.com", "admin.example.com",
		"staging.example.com", "dev.example.com", "test.example.com",
		"old.example.com", "vpn.example.com",
	}
	for _, w := range want {
		assert.Contains(t, subs, w, "expected subdomain %q", w)
	}
}

func TestParseSubfinderOutput_Empty(t *testing.T) {
	subs := parseSubfinderOutput(readFixture(t, "subfinder_empty.jsonl"))
	assert.Empty(t, subs)
}

// TestParseSubfinderOutput_MalformedDropsBadLines: per 6.1 Nuclei
// JSONL precedent, malformed lines are dropped (logged silently here
// since parseSubfinderOutput doesn't take a logger). Fixture has
// 5 lines: 3 valid + 1 bad-JSON + 1 missing-host.
func TestParseSubfinderOutput_MalformedDropsBadLines(t *testing.T) {
	subs := parseSubfinderOutput(readFixture(t, "subfinder_malformed.jsonl"))
	require.Len(t, subs, 3)
	for _, s := range subs {
		assert.Contains(t, s, "good")
	}
}

// TestParseSubfinderOutput_HostFieldRequired: a record without
// `host` field is skipped (parser extracts only host; no host = no
// subdomain).
func TestParseSubfinderOutput_HostFieldRequired(t *testing.T) {
	input := []byte(`{"input":"example.com","source":"crtsh"}` + "\n")
	subs := parseSubfinderOutput(input)
	assert.Empty(t, subs, "record without host field MUST NOT produce subdomain")
}
