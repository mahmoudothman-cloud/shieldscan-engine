package mobsf

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/odyssey/shieldscan-engine/internal/tools/docker/service"
)

// scanResponse echoes MobSF v4.4.6 POST /api/v1/scan acknowledgement
// per Phase 0 V4. Sync mode (Q4 lock): the call blocks until static
// analysis completes; response carries minimal echo fields.
type scanResponse struct {
	ScanType string `json:"scan_type"`
	FileName string `json:"file_name"`
	Hash     string `json:"hash"`
	Version  string `json:"version"`
}

// runScan triggers MobSF static analysis (sync mode per Q4 lock).
// Per Phase 0 V4: request is application/x-www-form-urlencoded with
// hash + scan_type + file_name fields; MobSF blocks until report
// generation completes (~12s on DIVA Phase 0 sample; much longer on
// full-sized binaries — ctx must carry a per-tool timeout per the
// orchestrator's ScanConfig.Timeout).
func runScan(ctx context.Context, client *service.Client, hash, scanType, fileName string) (*scanResponse, error) {
	form := url.Values{
		"hash":      {hash},
		"scan_type": {scanType},
		"file_name": {fileName},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		client.BaseURL+"/api/v1/scan", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("mobsf scan: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if client.AuthFunc != nil {
		client.AuthFunc(req)
	}

	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mobsf scan: do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := readAll(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("mobsf scan: status %d: %s", resp.StatusCode, truncate(body))
	}
	var sr scanResponse
	if err := json.Unmarshal(body, &sr); err != nil {
		return nil, fmt.Errorf("mobsf scan: parse response: %w", err)
	}
	return &sr, nil
}

// reportJSON fetches the structured static-analysis report per Phase 0
// V4. Endpoint: POST /api/v1/report_json with hash form field.
//
// Returns the raw JSON body; parser.go decodes per Phase 0 V11-V17
// section shapes.
func reportJSON(ctx context.Context, client *service.Client, hash string) ([]byte, error) {
	form := url.Values{"hash": {hash}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		client.BaseURL+"/api/v1/report_json", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("mobsf report_json: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if client.AuthFunc != nil {
		client.AuthFunc(req)
	}
	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mobsf report_json: do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := readAll(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("mobsf report_json: status %d: %s", resp.StatusCode, truncate(body))
	}
	return body, nil
}

// deleteScan removes a scan + its uploaded binary from MobSF storage
// per Phase 0 V18 (response: {"deleted":"yes"}). Best-effort cleanup;
// surfaces to caller for retry/logging discretion.
//
// Task 7.5d analogue verification (idempotency across surfaces;
// cumulative state-uniqueness) forward-pinned per Task 7.5c precedent.
func deleteScan(ctx context.Context, client *service.Client, hash string) error {
	form := url.Values{"hash": {hash}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		client.BaseURL+"/api/v1/delete_scan", strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("mobsf delete_scan: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if client.AuthFunc != nil {
		client.AuthFunc(req)
	}
	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("mobsf delete_scan: do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := readAll(resp)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("mobsf delete_scan: status %d: %s", resp.StatusCode, truncate(body))
	}
	return nil
}

// readAll drains an HTTP response body with a unified error message.
func readAll(resp *http.Response) ([]byte, error) {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("mobsf: read response body: %w", err)
	}
	return body, nil
}
