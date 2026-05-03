package recon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── parseHttpxOutput (5) ────────────────────────────────────────────

func TestParseHttpxOutput_Basic(t *testing.T) {
	hosts := parseHttpxOutput(readFixture(t, "httpx_basic.jsonl"))
	require.Len(t, hosts, 1)

	h := hosts[0]
	assert.Equal(t, "https://api.example.com", h.URL)
	assert.Equal(t, 200, h.StatusCode)
	assert.Equal(t, "Example API", h.Title)
	assert.Equal(t, []string{"Nginx", "Node.js"}, h.Tech)
	assert.Equal(t, "nginx", h.Webserver)
	assert.Equal(t, "application/json", h.ContentType)
}

func TestParseHttpxOutput_Multi(t *testing.T) {
	hosts := parseHttpxOutput(readFixture(t, "httpx_multi.jsonl"))
	// Multi fixture: 5 records, but 1 has failed:true → 4 LiveHosts
	require.Len(t, hosts, 4, "failed:true records MUST be excluded")

	// Status code spread.
	statuses := map[int]int{}
	for _, h := range hosts {
		statuses[h.StatusCode]++
	}
	assert.Equal(t, 2, statuses[200])
	assert.Equal(t, 1, statuses[403])
	assert.Equal(t, 1, statuses[404])
}

func TestParseHttpxOutput_Empty(t *testing.T) {
	hosts := parseHttpxOutput(readFixture(t, "httpx_empty.jsonl"))
	assert.Empty(t, hosts)
}

// TestParseHttpxOutput_DeadHostExcluded pins the failed:true filter.
// Fixture has only one record (failed:true) → 0 LiveHosts.
func TestParseHttpxOutput_DeadHostExcluded(t *testing.T) {
	hosts := parseHttpxOutput(readFixture(t, "httpx_dead_host.jsonl"))
	assert.Empty(t, hosts, "failed:true records MUST be excluded from output")
}

// TestParseHttpxOutput_FieldsExtracted pins the LiveHost 6-field
// shape (per H.NEW.1 extension beyond plan literal).
func TestParseHttpxOutput_FieldsExtracted(t *testing.T) {
	hosts := parseHttpxOutput(readFixture(t, "httpx_basic.jsonl"))
	require.Len(t, hosts, 1)
	h := hosts[0]
	// All 6 LiveHost fields populated from the fixture.
	assert.NotEmpty(t, h.URL)
	assert.NotZero(t, h.StatusCode)
	assert.NotEmpty(t, h.Title)
	assert.NotEmpty(t, h.Tech)
	assert.NotEmpty(t, h.Webserver)
	assert.NotEmpty(t, h.ContentType)
}
