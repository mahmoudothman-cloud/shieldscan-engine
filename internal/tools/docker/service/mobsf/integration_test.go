//go:build integration
// +build integration

// Package mobsf integration tests — run with `go test -tags integration`.
//
// Per Task 7.5e D-PLAN-4 build-tag convention precedent + SQLMap
// `integration_test.go` shieldscan-engine commit b48fef8 cross-package
// precedent (Drift #47 mirror per S3C2 pre-verification V-CO finding:
// no pre-existing MobSF integration_test.go in repo).
//
// Test exercises iOS scan path end-to-end per Task 7.4 V10 (Phase 0 v2
// v2 enablement task; shieldscan-docs commits 0347a79 design + 7c4fe75
// plan + d4f6ca7 V10 status RESOLVED):
//
//  1. Spin up MobSF v4.4.6 (opensecurity/mobile-security-framework-mobsf
//     :v4.4.6; image cross-task preserved from Task 7.4) on host port 18888
//  2. Upload /tmp/DVIA-v2-swift.ipa (SHA256 a0efb217...8817; 20.31 MB;
//     OWASP-derived per Drift #45 pivot from iGoat-Swift)
//  3. Trigger /api/v1/scan with scan_type="ipa"
//  4. Parse stdout via parseReport(body, "ios")
//  5. Assert iOS adaptors emit findings per V4 empirical baseline:
//     - ≥1 ats_violation (NSAllowsArbitraryLoads → high severity)
//     - ≥1 dylib_protection_missing
//     - ≥1 info_plist_finding
//     - ≥1 ios_url_scheme (dvia + dviaswift custom schemes)
//
// Y-INTEGRATION-TEST-SHAPE (a) single-platform iOS extension lock per
// V10 plan §3.1 + S3C2 pre-verification re-confirmation.
//
// Drift #44 bridge-IP fix NOT applicable per S3C2 pre-verification V-CR:
// test runs on host; MobSF API exposed via host port; no container→
// container topology requiring bridge-IP discovery.
package mobsf

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	dockerclient "github.com/docker/docker/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/go-connections/nat"
)

const (
	mobsfImage         = "opensecurity/mobile-security-framework-mobsf:v4.4.6"
	mobsfHostPort      = "18888"
	mobsfHostURL       = "http://localhost:" + mobsfHostPort
	mobsfContainerName = "mobsf-v10-integration-test"
	mobsfAPIKey        = "v10test123456789012345678901234567890123456789012345678901234"
	dviaIPAPath        = "/tmp/DVIA-v2-swift.ipa"
)

// TestIntegration_MobSF_iOS_DVIAv2_EndToEnd exercises iOS scan path
// end-to-end against MobSF v4.4.6 + DVIA-v2-swift v2.0 testbed.
// Per V4 Phase 0 v2 baseline: 4 iOS section types populate findings
// (info_plist + ats_analysis + dylib_analysis + bundle_url_types) +
// binary_analysis iOS dict shape per Q3 (a) collision resolution.
//
// Test orchestration: MobSF spinup (~30s) + IPA upload + scan (~10-15s)
// + parse + assert. Total wall-clock budget ~120s.
func TestIntegration_MobSF_iOS_DVIAv2_EndToEnd(t *testing.T) {
	if _, err := os.Stat(dviaIPAPath); os.IsNotExist(err) {
		t.Skipf("DVIA-v2-swift.ipa not present at %s; download from "+
			"https://github.com/prateek147/DVIA-v2/releases/download/v2.0/DVIA-v2-swift.ipa "+
			"per Task 7.4 V10 Drift #45 pivot", dviaIPAPath)
	}

	cli, err := dockerclient.NewClientWithOpts(
		dockerclient.FromEnv,
		dockerclient.WithAPIVersionNegotiation(),
	)
	require.NoError(t, err, "docker daemon must be reachable for integration tests")

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	cleanup := bootstrapMobSF(t, ctx, cli)
	t.Cleanup(cleanup)

	// Upload DVIA-v2 IPA
	uploadResp := mobsfUploadIPA(t, ctx, dviaIPAPath)
	require.Equal(t, "ipa", uploadResp.ScanType,
		"MobSF should detect iOS file type as ipa (V2 empirical)")
	require.NotEmpty(t, uploadResp.Hash, "upload hash required")

	// Trigger scan (returns full report directly per Phase 0 v2 V2.c)
	scanBody := mobsfTriggerScan(t, ctx, uploadResp.Hash, "ipa", "DVIA-v2-swift.ipa")
	require.Greater(t, len(scanBody), 1000, "scan report body should be substantial")

	// Parse via parseReport with platform="ios"
	findings, err := parseReport(scanBody, "ios")
	require.NoError(t, err, "parseReport should succeed on iOS report")
	require.NotEmpty(t, findings, "expected ≥1 finding from iOS scan")

	// Categorize findings per FindingType
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.FindingType]++
		assert.Equal(t, "ios", f.MobileOS, "all iOS findings must carry MobileOS=ios")
	}
	t.Logf("V4 baseline iOS scan PASSED: %d total findings; per-type: %+v",
		len(findings), counts)

	// V4 baseline assertions (Drift #35 closure-precedent shape applied to V10)
	assert.GreaterOrEqual(t, counts["ats_violation"], 1,
		"V4 baseline: ≥1 ats_violation (DVIA-v2 NSAllowsArbitraryLoads=true)")
	assert.GreaterOrEqual(t, counts["dylib_protection_missing"], 1,
		"V4 baseline: ≥1 dylib_protection_missing (DVIA-v2 has 20 dylibs)")
	assert.GreaterOrEqual(t, counts["info_plist_finding"], 1,
		"V4 baseline: ≥1 info_plist_finding (DVIA-v2 has NSAllowsArbitraryLoads+CFBundleURLTypes)")
	assert.GreaterOrEqual(t, counts["ios_url_scheme"], 1,
		"V4 baseline: ≥1 ios_url_scheme (DVIA-v2 dvia+dviaswift custom schemes)")
}

// ─── MobSF bootstrap + API helpers ───────────────────────────────────

// bootstrapMobSF pulls + spins up MobSF v4.4.6 container; returns
// cleanup. Container reaches ready within ~30s (V2 empirical).
func bootstrapMobSF(t *testing.T, ctx context.Context, cli *dockerclient.Client) func() {
	t.Helper()

	pullReader, err := cli.ImagePull(ctx, mobsfImage, image.PullOptions{})
	require.NoError(t, err, "MobSF image pull")
	_, _ = io.Copy(io.Discard, pullReader)
	_ = pullReader.Close()

	_ = cli.ContainerRemove(ctx, mobsfContainerName, container.RemoveOptions{Force: true})

	portKey := nat.Port("8000/tcp")
	createResp, err := cli.ContainerCreate(ctx,
		&container.Config{
			Image:        mobsfImage,
			ExposedPorts: nat.PortSet{portKey: struct{}{}},
			Env:          []string{"MOBSF_API_KEY=" + mobsfAPIKey},
		},
		&container.HostConfig{
			PortBindings: nat.PortMap{
				portKey: []nat.PortBinding{
					{HostIP: "127.0.0.1", HostPort: mobsfHostPort},
				},
			},
			AutoRemove: true,
		},
		nil, nil, mobsfContainerName,
	)
	require.NoError(t, err, "MobSF container create")

	cleanup := func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer stopCancel()
		_ = cli.ContainerStop(stopCtx, createResp.ID, container.StopOptions{})
	}

	require.NoError(t, cli.ContainerStart(ctx, createResp.ID, container.StartOptions{}),
		"MobSF container start")

	// Wait for HTTP readiness
	require.True(t, waitMobSFReady(60*time.Second),
		"MobSF HTTP not ready within 60s")

	return cleanup
}

func waitMobSFReady(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Get(mobsfHostURL + "/")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 400 {
				return true
			}
		}
		time.Sleep(3 * time.Second)
	}
	return false
}

type uploadAPIResp struct {
	Analyzer string `json:"analyzer"`
	Status   string `json:"status"`
	Hash     string `json:"hash"`
	ScanType string `json:"scan_type"`
	FileName string `json:"file_name"`
}

// mobsfUploadIPA POSTs the IPA via multipart/form-data to
// /api/v1/upload per V2.b empirical contract.
func mobsfUploadIPA(t *testing.T, ctx context.Context, path string) uploadAPIResp {
	t.Helper()
	fd, err := os.Open(path) //nolint:gosec // testbed path
	require.NoError(t, err, "open IPA")
	defer fd.Close()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "DVIA-v2-swift.ipa")
	require.NoError(t, err)
	_, err = io.Copy(part, fd)
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		mobsfHostURL+"/api/v1/upload", &body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", mobsfAPIKey)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err, "MobSF upload")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "upload status")

	var ur uploadAPIResp
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&ur))
	return ur
}

// mobsfTriggerScan posts /api/v1/scan and returns the full report
// body (per Phase 0 v2 V2.c empirical: /api/v1/scan returns full
// report directly).
func mobsfTriggerScan(t *testing.T, ctx context.Context, hash, scanType, fileName string) []byte {
	t.Helper()
	form := url.Values{}
	form.Set("hash", hash)
	form.Set("scan_type", scanType)
	form.Set("file_name", fileName)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		mobsfHostURL+"/api/v1/scan", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", mobsfAPIKey)

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err, "MobSF scan")
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "scan status")

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "read scan body")
	return body
}
