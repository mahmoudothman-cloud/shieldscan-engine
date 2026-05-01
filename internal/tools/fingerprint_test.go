package tools

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/odyssey/shieldscan-engine/internal/events"
)

// TestComputeFingerprint_Deterministic pins the canonical
// fingerprint algorithm: identical input fields produce identical
// fingerprints, today and forever (until a versioned migration).
//
// Table-driven over 6 distinct findings, computed twice each. Any
// future divergence between runs (e.g., from non-stable hash ordering
// or unintentional field additions) breaks this test.
func TestComputeFingerprint_Deterministic(t *testing.T) {
	cases := []struct {
		name string
		f    events.RawFinding
	}{
		{"web XSS",
			events.RawFinding{
				ToolName: "nuclei", FindingType: "xss",
				TargetURL: "https://app.example.com/search",
				Parameter: "q",
			}},
		{"SAST finding",
			events.RawFinding{
				ToolName: "semgrep", FindingType: "hardcoded-secret",
				CodeFile: "src/auth.py", CodeLine: 42,
			}},
		{"recon",
			events.RawFinding{
				ToolName: "subfinder", FindingType: "subdomain",
				TargetURL: "https://api.example.com",
			}},
		{"empty fields",
			events.RawFinding{}},
		{"unicode in URL",
			events.RawFinding{
				ToolName:    "nuclei",
				FindingType: "weak-cipher",
				TargetURL:   "https://例え.example.com",
			}},
		{"large code line",
			events.RawFinding{
				ToolName: "checkov", FindingType: "iac-misconfig",
				CodeFile: "terraform/main.tf", CodeLine: 9999999,
			}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fp1 := ComputeFingerprint(tc.f)
			fp2 := ComputeFingerprint(tc.f)
			require.NotEmpty(t, fp1, "fingerprint must be non-empty")
			assert.Equal(t, fp1, fp2, "same input must produce same fingerprint")
			// SHA-256 hex is 64 characters
			assert.Len(t, fp1, 64, "SHA-256 hex must be 64 characters")
		})
	}
}

// TestComputeFingerprint_DistinctInputs pins collision avoidance for
// representative permutations: changing any single contributing field
// produces a different fingerprint.
//
// Six contributing fields per TOOL-ARCHITECTURE.md §3.4:
//
//	tool_name | finding_type | target_url | parameter | code_file | code_line
//
// Each row mutates exactly one field from the baseline; the resulting
// fingerprint MUST differ from the baseline.
func TestComputeFingerprint_DistinctInputs(t *testing.T) {
	baseline := events.RawFinding{
		ToolName:    "nuclei",
		FindingType: "xss",
		TargetURL:   "https://app.example.com/search",
		Parameter:   "q",
		CodeFile:    "",
		CodeLine:    0,
	}
	baseFP := ComputeFingerprint(baseline)

	cases := []struct {
		name string
		mod  func(events.RawFinding) events.RawFinding
	}{
		{"different tool", func(f events.RawFinding) events.RawFinding { f.ToolName = "wapiti"; return f }},
		{"different finding type", func(f events.RawFinding) events.RawFinding { f.FindingType = "sqli"; return f }},
		{"different URL", func(f events.RawFinding) events.RawFinding { f.TargetURL = "https://other.example.com/x"; return f }},
		{"different parameter", func(f events.RawFinding) events.RawFinding { f.Parameter = "username"; return f }},
		{"add code_file", func(f events.RawFinding) events.RawFinding { f.CodeFile = "src/app.py"; return f }},
		{"add code_line", func(f events.RawFinding) events.RawFinding { f.CodeLine = 100; return f }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			modified := tc.mod(baseline)
			modFP := ComputeFingerprint(modified)
			assert.NotEqual(t, baseFP, modFP,
				"%s should produce different fingerprint than baseline", tc.name)
		})
	}
}

// TestComputeFingerprint_AllComponentsContribute is the systematic
// counterpart to TestComputeFingerprint_DistinctInputs. Builds a
// non-empty value for every contributing field; mutates each in turn
// and asserts the fingerprint changes. Catches the regression where
// a future refactor of the algorithm accidentally drops a component
// from the hash input.
func TestComputeFingerprint_AllComponentsContribute(t *testing.T) {
	full := events.RawFinding{
		ToolName:    "nuclei",
		FindingType: "xss",
		TargetURL:   "https://x.example.com",
		Parameter:   "q",
		CodeFile:    "src/handler.go",
		CodeLine:    7,
	}
	fullFP := ComputeFingerprint(full)

	mutators := map[string]func(events.RawFinding) events.RawFinding{
		"ToolName":    func(f events.RawFinding) events.RawFinding { f.ToolName += "X"; return f },
		"FindingType": func(f events.RawFinding) events.RawFinding { f.FindingType += "X"; return f },
		"TargetURL":   func(f events.RawFinding) events.RawFinding { f.TargetURL += "X"; return f },
		"Parameter":   func(f events.RawFinding) events.RawFinding { f.Parameter += "X"; return f },
		"CodeFile":    func(f events.RawFinding) events.RawFinding { f.CodeFile += "X"; return f },
		"CodeLine":    func(f events.RawFinding) events.RawFinding { f.CodeLine += 1; return f },
	}

	for fieldName, mut := range mutators {
		t.Run(fieldName, func(t *testing.T) {
			mutated := mut(full)
			mutFP := ComputeFingerprint(mutated)
			assert.NotEqual(t, fullFP, mutFP,
				"changing %s must change fingerprint (TOOL-ARCH §3.4 component coverage)",
				fieldName)
		})
	}
}
