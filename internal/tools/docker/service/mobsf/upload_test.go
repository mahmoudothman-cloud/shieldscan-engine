package mobsf

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/odyssey/shieldscan-engine/internal/tools/docker/service"
)

func newStubClient(baseURL string) *service.Client {
	return &service.Client{
		BaseURL:    baseURL,
		HTTPClient: &http.Client{},
		AuthFunc:   service.WithAPIKeyHeader(APIKeyHeader, stubAPIKey),
		Log:        noopLog(),
	}
}

func stageFile(t *testing.T, name string, body []byte) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, body, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestUploadFile_Happy(t *testing.T) {
	srv := newStubMobSFServer(t)
	client := newStubClient(srv.URL())
	path := stageFile(t, "diva.apk", []byte("APK"))

	resp, err := uploadFile(context.Background(), client, path)
	if err != nil {
		t.Fatalf("uploadFile: %v", err)
	}
	if resp.Hash != "stubhash123" {
		t.Fatalf("hash=%q; want stubhash123", resp.Hash)
	}
	if srv.lastUploadName != "diva.apk" {
		t.Fatalf("server saw filename=%q; want diva.apk", srv.lastUploadName)
	}
	if srv.uploadCalls.Load() != 1 {
		t.Fatalf("expected 1 upload call; got %d", srv.uploadCalls.Load())
	}
}

func TestUploadFile_Unauthorized(t *testing.T) {
	srv := newStubMobSFServer(t)
	client := newStubClient(srv.URL())
	client.AuthFunc = service.WithAPIKeyHeader(APIKeyHeader, "wrong-key")
	path := stageFile(t, "x.apk", []byte("X"))

	if _, err := uploadFile(context.Background(), client, path); err == nil {
		t.Fatal("expected unauthorized error")
	}
}

func TestUploadFile_MissingFile(t *testing.T) {
	srv := newStubMobSFServer(t)
	client := newStubClient(srv.URL())
	if _, err := uploadFile(context.Background(), client, "/nonexistent/path.apk"); err == nil {
		t.Fatal("expected open error")
	}
}
