package mobsf

import (
	"context"
	"errors"
	"fmt"
	"path"

	"github.com/odyssey/shieldscan-engine/internal/events"
	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/odyssey/shieldscan-engine/internal/tools/docker"
	"github.com/odyssey/shieldscan-engine/internal/tools/docker/service"
	"github.com/rs/zerolog"
)

// Image is the canonical MobSF v4.4.6 container image with multi-arch
// digest pin (Phase 0 V1 verified: amd64 + arm64). Per VERSIONS.md §2.5
// + ADR-006 image-pinning + Phase 0 V1 resolution.
const Image = "opensecurity/mobile-security-framework-mobsf@sha256:72311e3553ca2c21043923cace27ed99f800cd641e9368160406779516dd774e"

// ContainerPort is the MobSF web/API listen port inside the container.
const ContainerPort = 8000

// APIKeyHeader is the canonical MobSF auth header name per Phase 0 V3.
// (#nosec G101 — header name, not credential value.)
const APIKeyHeader = "X-Mobsf-Api-Key" //nolint:gosec // header name, not credential

// MobileConfig carries the per-scan mobile-specific job fields the
// orchestrator extracts from JobMobileConfig. Passed via
// tools.ScanConfig.ExtraArgs keys (mobsf.platform + mobsf.analysis_type)
// to avoid retroactively widening ScanConfig (per "NOT IN SCOPE FOR
// PHASE 1: ❌ DO NOT add ScanConfig fields").
const (
	extraArgPlatform     = "mobsf.platform"
	extraArgAnalysisType = "mobsf.analysis_type"
)

// Config carries MobSF-consumer-specific tunables passed to NewRunner
// / NewBuildScan. Mobile-job-specific fields (platform, upload_ref,
// analysis_type) flow through tools.Target.MobileUploadRef +
// tools.ScanConfig.ExtraArgs per Q3 lock; Config carries only static
// consumer-injected values.
type Config struct {
	// APIKey is the MobSF REST API key (env-supplied to the container
	// via MOBSF_API_KEY). Required.
	APIKey string

	// R2 carries Cloudflare R2 credentials for binary staging. Required
	// when MobileUploadRef has r2:// prefix.
	R2 R2Config

	// FetcherOverride is a test-injection point. nil in production;
	// tests substitute a fake r2Fetcher.
	FetcherOverride r2Fetcher
}

// NewBuildScan returns the BuildScan closure for
// service.DockerServiceRunner.BuildScan field. Lifecycle per Task 7.4
// design doc §3.3:
//
//  1. Validate target (mobile-only; static-only v1; ext per Q2(iv))
//  2. Fetch APK/IPA from R2 → staging file
//  3. POST /api/v1/upload → get hash
//  4. POST /api/v1/scan → sync analysis
//  5. POST /api/v1/report_json → fetch report
//  6. Parse → []RawFinding
//  7. POST /api/v1/delete_scan (best-effort; logs warning on failure)
//
// Identity-field enrichment handled by DockerServiceRunner.Run.
func NewBuildScan(cfg Config) func(context.Context, tools.Target, tools.ScanConfig, *service.Client) ([]events.RawFinding, error) {
	return func(ctx context.Context, target tools.Target, scanCfg tools.ScanConfig, client *service.Client) ([]events.RawFinding, error) {
		if cfg.APIKey == "" {
			return nil, errors.New("mobsf: APIKey required")
		}
		if target.TargetType != "mobile" {
			return nil, fmt.Errorf("mobsf: target_type must be 'mobile'; got %q", target.TargetType)
		}

		platform := scanCfg.ExtraArgs[extraArgPlatform]
		analysisType := scanCfg.ExtraArgs[extraArgAnalysisType]
		if analysisType == "" {
			analysisType = AnalysisStatic // v1 default
		}

		mt, err := validateMobileTarget(target.MobileUploadRef, platform, analysisType)
		if err != nil {
			return nil, err
		}

		// Per MobSF R2 pre-signed URL task Q3 (a) preference + fallback
		// (shieldscan-docs b25e9ba design + 721f788 plan + 8f71b01 SPEC
		// addendums + shieldscan-api 824853c orchestrator emission):
		// when Target.SignedFetchURL is populated, prefer httpFetcher
		// (plain HTTP GET; no worker-side R2 credentials required); else
		// fall back to r2Fetcher path (FetcherOverride for tests OR
		// production s3R2Fetcher) per Q3 (a) backward-compat migration
		// window. r2.go + s3R2Fetcher retention per Q7-refined; deletion
		// forward-pinned to "Begin MobSF R2 migration-close task".
		var fetcher r2Fetcher
		if target.SignedFetchURL != "" {
			// Derive staged-file basename hint from UploadRef so MobSF
			// /api/v1/upload sees the right extension (Task 7.4 Phase 0
			// V2 empirical: extension drives platform/parser routing).
			hint := path.Base(mt.UploadRef)
			fetcher = newHTTPFetcher(target.SignedFetchURL, hint)
		} else {
			fetcher = cfg.FetcherOverride
			if fetcher == nil {
				prodFetcher, err := newR2Fetcher(cfg.R2, client.Log)
				if err != nil {
					return nil, err
				}
				fetcher = prodFetcher
			}
		}

		localPath, cleanup, err := fetcher.Fetch(ctx, mt.UploadRef)
		if err != nil {
			return nil, fmt.Errorf("mobsf: fetch binary: %w", err)
		}
		defer cleanup()

		uploaded, err := uploadFile(ctx, client, localPath)
		if err != nil {
			return nil, fmt.Errorf("mobsf: upload: %w", err)
		}

		if _, err := runScan(ctx, client, uploaded.Hash, uploaded.ScanType, uploaded.FileName); err != nil {
			return nil, fmt.Errorf("mobsf: scan: %w", err)
		}

		body, err := reportJSON(ctx, client, uploaded.Hash)
		if err != nil {
			return nil, fmt.Errorf("mobsf: report_json: %w", err)
		}

		findings, err := parseReport(body, mt.Platform)
		if err != nil {
			return nil, fmt.Errorf("mobsf: parse: %w", err)
		}

		// Best-effort delete_scan (Q5 ephemeral default short-circuits
		// most cleanup; explicit delete_scan reduces image-layer churn
		// across rapid re-scans of overlapping hashes).
		if delErr := deleteScan(ctx, client, uploaded.Hash); delErr != nil {
			client.Log.Warn().Err(delErr).Str("hash", uploaded.Hash).Msg("mobsf: delete_scan failed (best-effort)")
		}

		return findings, nil
	}
}

// NewRunner constructs the DockerServiceRunner consumer wiring for
// MobSF per Task 7.4 + Task 7.5b framework + Q5 Option β ephemeral
// default. Symmetric with zap.NewRunner pattern.
func NewRunner(cli docker.DockerClient, cfg Config, log zerolog.Logger) *service.DockerServiceRunner {
	mobsfLog := log.With().Str("tool", "mobsf").Logger()
	return &service.DockerServiceRunner{
		ToolName:     "mobsf",
		ToolCategory: "mast",
		Cli:          cli,
		ServiceConfig: service.ServiceConfig{
			Image:              Image,
			ContainerPort:      ContainerPort,
			EphemeralContainer: true, // Q5 Option β v1 default (Task 7.5d analogue verification)
			ReadinessEndpoint:  "/",
			AuthFunc:           service.WithAPIKeyHeader(APIKeyHeader, cfg.APIKey),
		},
		BuildScan: NewBuildScan(cfg),
		Log:       mobsfLog,
	}
}
