package mobsf

import (
	"context"
	"net/http"
	"net/http/httptest"
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
	if err == nil || !strings.Contains(err.Error(), "fetch binary") {
		t.Fatalf("expected fetch binary error; got %v", err)
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

// ─── MobSF R2 pre-signed URL task — Q3 (a) preference + fallback tests ───

// TestNewBuildScan_PrefersHTTPFetcherWhenSignedFetchURLPresent verifies
// Q3 (a) preference: when Target.SignedFetchURL is populated, the
// consumer uses plain HTTP GET via httpFetcher instead of r2Fetcher
// (no FetcherOverride consumed).
func TestNewBuildScan_PrefersHTTPFetcherWhenSignedFetchURLPresent(t *testing.T) {
	srv := newStubMobSFServer(t)
	client := newStubClient(srv.URL())

	binSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.android.package-archive")
		_, _ = w.Write([]byte("PK\x03\x04stub-apk-binary-bytes"))
	}))
	t.Cleanup(binSrv.Close)

	// poisonedFetcher would fail if invoked — verifies SignedFetchURL
	// path bypasses r2Fetcher entirely per Q3 (a) preference.
	poisonedFetcher := &fakeFetcher{failOnce: true}
	build := NewBuildScan(Config{APIKey: stubAPIKey, FetcherOverride: poisonedFetcher})

	_, err := build(context.Background(),
		tools.Target{
			TargetType:      "mobile",
			MobileUploadRef: "r2://bucket/diva.apk",
			SignedFetchURL:  binSrv.URL + "/diva.apk",
		},
		tools.ScanConfig{ExtraArgs: map[string]string{extraArgPlatform: PlatformAndroid}},
		client,
	)
	if err != nil {
		t.Fatalf("expected SignedFetchURL path success; got %v", err)
	}
	if poisonedFetcher.fetchCalls.Load() != 0 {
		t.Fatal("r2Fetcher must NOT be invoked when SignedFetchURL present per Q3 (a)")
	}
}

// TestNewBuildScan_FallsBackToR2FetcherWhenSignedFetchURLAbsent verifies
// Q3 (a) fallback: when Target.SignedFetchURL is empty, consumer uses
// the existing r2Fetcher path (FetcherOverride for tests). Backward-
// compat migration-window behavior; matches pre-R2-task baseline.
func TestNewBuildScan_FallsBackToR2FetcherWhenSignedFetchURLAbsent(t *testing.T) {
	srv := newStubMobSFServer(t)
	client := newStubClient(srv.URL())

	fetcher := &fakeFetcher{}
	build := NewBuildScan(Config{APIKey: stubAPIKey, FetcherOverride: fetcher})
	_, err := build(context.Background(),
		tools.Target{
			TargetType:      "mobile",
			MobileUploadRef: "r2://bucket/diva.apk",
			// SignedFetchURL deliberately omitted (empty) → fallback path
		},
		tools.ScanConfig{ExtraArgs: map[string]string{extraArgPlatform: PlatformAndroid}},
		client,
	)
	if err != nil {
		t.Fatalf("expected r2Fetcher fallback success; got %v", err)
	}
	if fetcher.fetchCalls.Load() != 1 {
		t.Fatalf("r2Fetcher should be invoked once in fallback; got %d", fetcher.fetchCalls.Load())
	}
}

// TestNewBuildScan_HTTPFetcherFailureSurfacesError verifies httpFetcher
// 5xx error path surfaces as fetch failure (analog to r2Fetcher
// failure handling).
func TestNewBuildScan_HTTPFetcherFailureSurfacesError(t *testing.T) {
	srv := newStubMobSFServer(t)
	client := newStubClient(srv.URL())

	binSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(binSrv.Close)

	build := NewBuildScan(Config{APIKey: stubAPIKey})
	_, err := build(context.Background(),
		tools.Target{
			TargetType:      "mobile",
			MobileUploadRef: "r2://bucket/diva.apk",
			SignedFetchURL:  binSrv.URL + "/diva.apk",
		},
		tools.ScanConfig{ExtraArgs: map[string]string{extraArgPlatform: PlatformAndroid}},
		client,
	)
	if err == nil {
		t.Fatal("expected error on 500 from pre-signed URL")
	}
	if !strings.Contains(err.Error(), "fetch") {
		t.Fatalf("expected fetch error; got %v", err)
	}
}
