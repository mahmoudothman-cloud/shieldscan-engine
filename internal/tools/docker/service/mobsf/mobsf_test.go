package mobsf

import (
	"context"
	"strings"
	"testing"

	"github.com/odyssey/shieldscan-engine/internal/events"
	"github.com/odyssey/shieldscan-engine/internal/tools"
)

func TestNewBuildScan_HappyPath(t *testing.T) {
	srv := newStubMobSFServer(t)
	client := newStubClient(srv.URL())

	fetcher := &fakeFetcher{}
	cfg := Config{
		APIKey:          stubAPIKey,
		FetcherOverride: fetcher,
		R2:              R2Config{
			// Not used because FetcherOverride is non-nil.
		},
	}
	build := NewBuildScan(cfg)
	findings, err := build(context.Background(),
		tools.Target{
			TargetType:      "mobile",
			MobileUploadRef: "r2://bucket/path/diva.apk",
		},
		tools.ScanConfig{
			ExtraArgs: map[string]string{
				extraArgPlatform:     PlatformAndroid,
				extraArgAnalysisType: AnalysisStatic,
			},
		},
		client,
	)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected non-empty findings")
	}
	// Server should have observed the upload + scan + report + delete.
	if srv.uploadCalls.Load() != 1 || srv.scanCalls.Load() != 1 ||
		srv.reportCalls.Load() != 1 || srv.deleteCalls.Load() != 1 {
		t.Fatalf("call counts: upload=%d scan=%d report=%d delete=%d",
			srv.uploadCalls.Load(), srv.scanCalls.Load(),
			srv.reportCalls.Load(), srv.deleteCalls.Load())
	}
	if fetcher.fetchCalls.Load() != 1 {
		t.Fatalf("expected 1 fetch; got %d", fetcher.fetchCalls.Load())
	}
	// MobileOS propagated.
	for _, f := range findings {
		if f.MobileOS != "android" {
			t.Fatalf("MobileOS=%q on finding %q", f.MobileOS, f.Title)
		}
	}
}

func TestNewBuildScan_WrongTargetType(t *testing.T) {
	srv := newStubMobSFServer(t)
	client := newStubClient(srv.URL())
	build := NewBuildScan(Config{APIKey: stubAPIKey, FetcherOverride: &fakeFetcher{}})
	_, err := build(context.Background(),
		tools.Target{TargetType: "web", URL: "https://example.com"},
		tools.ScanConfig{ExtraArgs: map[string]string{extraArgPlatform: "android"}},
		client,
	)
	if err == nil || !strings.Contains(err.Error(), "target_type must be 'mobile'") {
		t.Fatalf("expected target_type error; got %v", err)
	}
}

func TestNewBuildScan_MissingAPIKey(t *testing.T) {
	srv := newStubMobSFServer(t)
	client := newStubClient(srv.URL())
	build := NewBuildScan(Config{})
	_, err := build(context.Background(),
		tools.Target{TargetType: "mobile", MobileUploadRef: "r2://b/x.apk"},
		tools.ScanConfig{ExtraArgs: map[string]string{extraArgPlatform: "android"}},
		client,
	)
	if err == nil || !strings.Contains(err.Error(), "APIKey required") {
		t.Fatalf("expected APIKey required; got %v", err)
	}
}

func TestNewBuildScan_FetcherFailure(t *testing.T) {
	srv := newStubMobSFServer(t)
	client := newStubClient(srv.URL())
	fetcher := &fakeFetcher{failOnce: true}
	build := NewBuildScan(Config{APIKey: stubAPIKey, FetcherOverride: fetcher})
	_, err := build(context.Background(),
		tools.Target{TargetType: "mobile", MobileUploadRef: "r2://b/x.apk"},
		tools.ScanConfig{ExtraArgs: map[string]string{extraArgPlatform: "android"}},
		client,
	)
	if err == nil || !strings.Contains(err.Error(), "r2 fetch") {
		t.Fatalf("expected r2 fetch error; got %v", err)
	}
}

func TestNewBuildScan_DefaultsStaticAnalysis(t *testing.T) {
	srv := newStubMobSFServer(t)
	client := newStubClient(srv.URL())
	build := NewBuildScan(Config{APIKey: stubAPIKey, FetcherOverride: &fakeFetcher{}})
	// Omit analysis_type → should default to static.
	_, err := build(context.Background(),
		tools.Target{TargetType: "mobile", MobileUploadRef: "r2://b/x.apk"},
		tools.ScanConfig{ExtraArgs: map[string]string{extraArgPlatform: "android"}},
		client,
	)
	if err != nil {
		t.Fatalf("default static path: %v", err)
	}
}

// TestNewBuildScan_RawFindingShape verifies the BuildScan output remains
// compatible with the DockerServiceRunner.Run enrichment loop (identity
// fields populated by the runner, not by the consumer).
func TestNewBuildScan_RawFindingShape(t *testing.T) {
	srv := newStubMobSFServer(t)
	client := newStubClient(srv.URL())
	build := NewBuildScan(Config{APIKey: stubAPIKey, FetcherOverride: &fakeFetcher{}})
	findings, err := build(context.Background(),
		tools.Target{TargetType: "mobile", MobileUploadRef: "r2://b/x.apk"},
		tools.ScanConfig{ExtraArgs: map[string]string{extraArgPlatform: "android"}},
		client,
	)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for _, f := range findings {
		// Identity fields MUST be left empty (runner populates).
		if f.ToolName != "" || f.EngineCategory != "" || f.DiscoveredAt != "" || f.Fingerprint != "" {
			t.Fatalf("consumer must leave identity fields empty for runner enrichment: %+v", f)
		}
		// At minimum: title + severity set.
		if f.Title == "" || f.Severity == "" {
			t.Fatalf("incomplete finding: %+v", f)
		}
	}
	// Sanity: ensure the events.RawFinding type alias surfaces.
	_ = events.RawFinding{}
}
