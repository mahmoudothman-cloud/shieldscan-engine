package source

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewStagingManager_RejectsEmptyBasePath(t *testing.T) {
	_, err := NewStagingManager("")
	if err == nil || !strings.Contains(err.Error(), "basePath required") {
		t.Fatalf("expected basePath-required error; got %v", err)
	}
}

func TestStagingDirForScan_JoinsBasePathAndScanID(t *testing.T) {
	mgr, err := NewStagingManager("/tmp/sif")
	if err != nil {
		t.Fatalf("NewStagingManager: %v", err)
	}
	got, err := mgr.StagingDirForScan("scan-abc")
	if err != nil {
		t.Fatalf("StagingDirForScan: %v", err)
	}
	if got != filepath.Join("/tmp/sif", "scan-abc") {
		t.Fatalf("unexpected staging dir: %q", got)
	}
}

func TestStagingDirForScan_RejectsEmptyScanID(t *testing.T) {
	mgr, _ := NewStagingManager("/tmp/sif")
	_, err := mgr.StagingDirForScan("")
	if err == nil || !strings.Contains(err.Error(), "scanID required") {
		t.Fatalf("expected scanID-required error; got %v", err)
	}
}

func TestCleanup_RemovesPopulatedStagingTree(t *testing.T) {
	base := t.TempDir()
	mgr, err := NewStagingManager(base)
	if err != nil {
		t.Fatalf("NewStagingManager: %v", err)
	}
	scanDir, err := mgr.StagingDirForScan("scan-xyz")
	if err != nil {
		t.Fatalf("StagingDirForScan: %v", err)
	}
	// Populate the staging tree (mirrors a real clone-then-scan).
	if err := os.MkdirAll(filepath.Join(scanDir, "nested"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(scanDir, "package-lock.json"), []byte("{}"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := mgr.Cleanup("scan-xyz"); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(scanDir); !os.IsNotExist(err) {
		t.Fatalf("staging dir should be gone; stat err=%v", err)
	}
}

func TestCleanup_IdempotentOnMissingDir(t *testing.T) {
	mgr, _ := NewStagingManager(t.TempDir())
	if err := mgr.Cleanup("never-existed"); err != nil {
		t.Fatalf("Cleanup of missing dir should be idempotent; got %v", err)
	}
}
