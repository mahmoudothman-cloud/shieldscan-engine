package sqlmap

import (
	"reflect"
	"strings"
	"testing"

	"github.com/odyssey/shieldscan-engine/internal/tools"
)

func TestBuildArgs_QuickDepth(t *testing.T) {
	got := buildArgs(tools.Target{URL: "http://example.test/?id=1"}, tools.ScanConfig{Depth: "quick"})
	want := []string{
		"sqlmap",
		"-u", "http://example.test/?id=1",
		"--batch",
		"--disable-coloring",
		"--level=1",
		"--risk=1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("quick depth got=%v\nwant=%v", got, want)
	}
}

func TestBuildArgs_DefaultEmptyDepth(t *testing.T) {
	// Empty cfg.Depth must default to quick mapping (level=1, risk=1)
	got := buildArgs(tools.Target{URL: "http://example.test/?id=1"}, tools.ScanConfig{})
	if !contains(got, "--level=1") || !contains(got, "--risk=1") {
		t.Errorf("default depth expected level=1 risk=1; got %v", got)
	}
}

func TestBuildArgs_StandardDepth(t *testing.T) {
	got := buildArgs(tools.Target{URL: "http://x.test/q?p=1"}, tools.ScanConfig{Depth: "standard"})
	if !contains(got, "--level=3") || !contains(got, "--risk=2") {
		t.Errorf("standard depth expected level=3 risk=2; got %v", got)
	}
}

func TestBuildArgs_DeepDepth(t *testing.T) {
	got := buildArgs(tools.Target{URL: "http://x.test/q?p=1"}, tools.ScanConfig{Depth: "deep"})
	if !contains(got, "--level=5") || !contains(got, "--risk=3") {
		t.Errorf("deep depth expected level=5 risk=3; got %v", got)
	}
}

// TestBuildArgs_UnknownDepth verifies defensive forward-compat — an
// unrecognized Depth value falls through to quick mapping (level=1,
// risk=1) per depthToLevelRisk default branch. Surface drift if
// implementation chooses different default in future.
func TestBuildArgs_UnknownDepth(t *testing.T) {
	got := buildArgs(tools.Target{URL: "http://x.test/q?p=1"}, tools.ScanConfig{Depth: "extreme"})
	if !contains(got, "--level=1") || !contains(got, "--risk=1") {
		t.Errorf("unknown depth expected quick-mapping default; got %v", got)
	}
}

func TestBuildArgs_EmptyURL(t *testing.T) {
	got := buildArgs(tools.Target{URL: ""}, tools.ScanConfig{Depth: "standard"})
	if got != nil {
		t.Errorf("empty URL expected nil argv (D-PLAN-2 pattern); got %v", got)
	}
}

func TestBuildArgs_Argv0_SqlmapBinary(t *testing.T) {
	got := buildArgs(tools.Target{URL: "http://x.test/"}, tools.ScanConfig{})
	if len(got) == 0 || got[0] != "sqlmap" {
		t.Errorf("argv[0]=%q; want \"sqlmap\" (Container.Exec full-argv convention)", strings.Join(got[:1], ""))
	}
}

func TestBuildArgs_BatchAndDisableColoring(t *testing.T) {
	// Both flags must appear regardless of Depth value
	for _, depth := range []string{"quick", "standard", "deep", "", "unknown"} {
		got := buildArgs(tools.Target{URL: "http://x.test/"}, tools.ScanConfig{Depth: depth})
		if !contains(got, "--batch") {
			t.Errorf("depth=%q: --batch flag missing in %v", depth, got)
		}
		if !contains(got, "--disable-coloring") {
			t.Errorf("depth=%q: --disable-coloring flag missing in %v", depth, got)
		}
	}
}

// TestBuildArgs_URLAfterFlag verifies argv shape: "-u" immediately
// followed by the URL string (sqlmap CLI convention).
func TestBuildArgs_URLAfterFlag(t *testing.T) {
	url := "http://example.test/sqli?id=1&Submit=Submit"
	got := buildArgs(tools.Target{URL: url}, tools.ScanConfig{})
	idx := indexOf(got, "-u")
	if idx < 0 {
		t.Fatalf("-u flag not found in %v", got)
	}
	if idx+1 >= len(got) {
		t.Fatalf("-u flag at end with no URL value: %v", got)
	}
	if got[idx+1] != url {
		t.Errorf("-u value=%q; want %q", got[idx+1], url)
	}
}

func TestDepthToLevelRisk(t *testing.T) {
	cases := []struct {
		depth, wantLevel, wantRisk string
	}{
		{"quick", "1", "1"},
		{"standard", "3", "2"},
		{"deep", "5", "3"},
		{"", "1", "1"},
		{"unknown", "1", "1"},
	}
	for _, c := range cases {
		level, risk := depthToLevelRisk(c.depth)
		if level != c.wantLevel || risk != c.wantRisk {
			t.Errorf("depthToLevelRisk(%q)=(%q,%q); want (%q,%q)",
				c.depth, level, risk, c.wantLevel, c.wantRisk)
		}
	}
}

// ─── helpers ──────────────────────────────────────────────────────────

func contains(slice []string, value string) bool {
	for _, s := range slice {
		if s == value {
			return true
		}
	}
	return false
}

func indexOf(slice []string, value string) int {
	for i, s := range slice {
		if s == value {
			return i
		}
	}
	return -1
}
