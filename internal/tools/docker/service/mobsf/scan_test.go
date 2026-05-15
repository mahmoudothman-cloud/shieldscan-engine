package mobsf

import (
	"context"
	"testing"
)

func TestRunScan_Happy(t *testing.T) {
	srv := newStubMobSFServer(t)
	client := newStubClient(srv.URL())
	resp, err := runScan(context.Background(), client, "h1", "apk", "f.apk")
	if err != nil {
		t.Fatalf("runScan: %v", err)
	}
	if resp.Hash != "h1" {
		t.Fatalf("Hash=%q; want h1", resp.Hash)
	}
	if srv.lastScanHash != "h1" {
		t.Fatalf("server saw hash=%q; want h1", srv.lastScanHash)
	}
}

func TestRunScan_500RetryableSurface(t *testing.T) {
	srv := newStubMobSFServer(t)
	srv.failNext["/api/v1/scan"] = 1
	client := newStubClient(srv.URL())
	if _, err := runScan(context.Background(), client, "h1", "apk", "f.apk"); err == nil {
		t.Fatal("expected error on 500")
	}
}

func TestReportJSON_Happy(t *testing.T) {
	srv := newStubMobSFServer(t)
	client := newStubClient(srv.URL())
	body, err := reportJSON(context.Background(), client, "h1")
	if err != nil {
		t.Fatalf("reportJSON: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("empty body")
	}
	if srv.reportCalls.Load() != 1 {
		t.Fatalf("expected 1 call; got %d", srv.reportCalls.Load())
	}
}

func TestDeleteScan_Happy(t *testing.T) {
	srv := newStubMobSFServer(t)
	client := newStubClient(srv.URL())
	if err := deleteScan(context.Background(), client, "h1"); err != nil {
		t.Fatalf("deleteScan: %v", err)
	}
	if srv.deleteCalls.Load() != 1 {
		t.Fatalf("expected 1 delete call; got %d", srv.deleteCalls.Load())
	}
}

func TestDeleteScan_Unauthorized(t *testing.T) {
	srv := newStubMobSFServer(t)
	client := newStubClient(srv.URL())
	client.AuthFunc = nil // no auth
	if err := deleteScan(context.Background(), client, "h1"); err == nil {
		t.Fatal("expected unauthorized")
	}
}
