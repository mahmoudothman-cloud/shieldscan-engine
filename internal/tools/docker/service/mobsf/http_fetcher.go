// Package mobsf — httpFetcher implementation for MobSF R2 pre-signed
// URL pattern (Y-HTTP-FETCHER-LOCATION (a) lock per R2 plan §3.3).
//
// Per MobSF R2 pre-signed URL task (shieldscan-docs commits b25e9ba
// design + 721f788 plan + 8f71b01 SPEC ADR-013/ADR-014 R2 addendums
// + shieldscan-api 824853c orchestrator dispatch+audit): when
// JobMobileConfig.SignedFetchURL is populated, NewBuildScan selects
// httpFetcher over s3R2Fetcher per Q3 (a) preference (engine
// consumes pre-authorized HTTPS resource without worker-side R2
// credentials).
//
// httpFetcher satisfies the r2Fetcher interface; mirrors s3R2Fetcher
// temp-file staging pattern for parity at the MobSF upload-stage
// boundary. ctx cancellation propagates to the HTTP GET via
// http.NewRequestWithContext.
package mobsf

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"time"
)

// httpFetcher consumes a pre-signed HTTPS URL (typically R2
// generate_presigned_url output) via plain HTTP GET; stages the
// response body to a worker-local temp file. Q7-refined: coexists
// with s3R2Fetcher during migration window; deletion of r2.go +
// s3R2Fetcher forward-pinned to "Begin MobSF R2 migration-close
// task" when SignedFetchURL adoption empirically stable.
type httpFetcher struct {
	url      string
	hintName string // optional: hint for staged file basename (extension drives MobSF parser routing)
}

// newHTTPFetcher constructs an httpFetcher for the given pre-signed
// URL. hintName is the desired staged-file basename (e.g.,
// "DVIA-v2-swift.ipa"); MobSF's /api/v1/upload uses the basename's
// extension for platform/parser routing (Task 7.4 Phase 0 V2
// empirical). Empty hintName falls back to the URL path's basename.
func newHTTPFetcher(url, hintName string) *httpFetcher {
	return &httpFetcher{url: url, hintName: hintName}
}

// Fetch downloads the pre-signed URL body to a worker-local temp
// file. uploadRef parameter is unused (preserved for r2Fetcher
// interface compatibility); the URL is captured at construction
// time. Returns localPath + cleanup closure (caller defers) +
// error per r2Fetcher contract.
//
// ctx cancellation propagates through http.NewRequestWithContext to
// the in-flight HTTP GET. Standard 10-minute default timeout via
// dedicated http.Client matches Q2 (a) 600s URL expiry posture.
func (f *httpFetcher) Fetch(ctx context.Context, _ string) (string, func(), error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return "", nil, fmt.Errorf("mobsf http_fetcher: build request: %w", err)
	}
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("mobsf http_fetcher: GET: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return "", nil, fmt.Errorf(
			"mobsf http_fetcher: HTTP %d from pre-signed URL", resp.StatusCode,
		)
	}

	// Stage to worker-local /tmp. Preserve basename extension so
	// MobSF /api/v1/upload sees a file with the right extension
	// (Task 7.4 Phase 0 V2: extension drives platform/parser routing
	// inside MobSF). Per Q1 (β) sibling-field decision: hintName
	// SHOULD be derived from JobMobileConfig.UploadRef basename
	// when available; URL path basename used as fallback.
	baseName := f.hintName
	if baseName == "" {
		baseName = path.Base(req.URL.Path)
	}
	tmpDir, err := os.MkdirTemp("", "mobsf-http-*")
	if err != nil {
		return "", nil, fmt.Errorf("mobsf http_fetcher: mkdtemp: %w", err)
	}
	localPath := filepath.Join(tmpDir, baseName)

	cleanup := func() {
		_ = os.RemoveAll(tmpDir)
	}

	out, err := os.Create(localPath) //nolint:gosec // localPath under MkdirTemp
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("mobsf http_fetcher: create %s: %w", localPath, err)
	}
	defer func() { _ = out.Close() }()

	if _, err := io.Copy(out, resp.Body); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("mobsf http_fetcher: copy body: %w", err)
	}
	return localPath, cleanup, nil
}
