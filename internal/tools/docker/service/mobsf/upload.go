package mobsf

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path"

	"github.com/odyssey/shieldscan-engine/internal/tools/docker/service"
)

// uploadResponse mirrors MobSF v4.4.6 POST /api/v1/upload response
// per Phase 0 V4 grounded reality: {hash, scan_type, file_name}.
// MobSF surfaces additional fields (e.g., status keys on newer
// versions); encoding/json silently ignores unknowns.
type uploadResponse struct {
	Hash     string `json:"hash"`
	ScanType string `json:"scan_type"`
	FileName string `json:"file_name"`
}

// uploadFile POSTs the staged binary at localPath to MobSF
// /api/v1/upload as multipart/form-data with field name "file".
// Returns the parsed uploadResponse (hash + scan_type detected by
// MobSF + file_name echo).
//
// ctx cancellation propagates to the multipart request.
//
// Auth: framework Client.AuthFunc injects X-Mobsf-Api-Key header
// (consumer-side AuthFunc construction in NewRunner).
func uploadFile(ctx context.Context, client *service.Client, localPath string) (*uploadResponse, error) {
	fd, err := os.Open(localPath) //nolint:gosec // localPath comes from r2.Fetch staging
	if err != nil {
		return nil, fmt.Errorf("mobsf upload: open %s: %w", localPath, err)
	}
	defer func() { _ = fd.Close() }()

	// Build multipart body. Buffer in memory — APK/IPA payloads are
	// typically <100MB; streamed writer is forward-pin if memory pressure
	// surfaces.
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", path.Base(localPath))
	if err != nil {
		return nil, fmt.Errorf("mobsf upload: create form file: %w", err)
	}
	if _, err := io.Copy(part, fd); err != nil {
		return nil, fmt.Errorf("mobsf upload: stream body: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("mobsf upload: close multipart writer: %w", err)
	}

	url := client.BaseURL + "/api/v1/upload"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &body)
	if err != nil {
		return nil, fmt.Errorf("mobsf upload: build request: %w", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	if client.AuthFunc != nil {
		client.AuthFunc(req)
	}

	resp, err := client.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mobsf upload: do request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("mobsf upload: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("mobsf upload: status %d: %s", resp.StatusCode, truncate(respBody))
	}
	var ur uploadResponse
	if err := json.Unmarshal(respBody, &ur); err != nil {
		return nil, fmt.Errorf("mobsf upload: parse response: %w", err)
	}
	if ur.Hash == "" {
		return nil, fmt.Errorf("mobsf upload: response missing hash: %s", truncate(respBody))
	}
	return &ur, nil
}

// truncate caps a bytes slice to a readable prefix for error messages
// (avoid leaking giant response bodies into logs).
func truncate(b []byte) string {
	const maxLen = 256
	if len(b) <= maxLen {
		return string(b)
	}
	return string(b[:maxLen]) + "..."
}
