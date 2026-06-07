package source

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// StagingManager owns the per-scan tempdir lifecycle for source-
// acquisition. Construction takes a base path (typically
// $TRIVY_SCAN_BASE_PATH) so the existing trivy-fs warm-pool bind
// mount surfaces the staging tree as /scan/<scan-id> inside the
// container, ReadOnly per Q-STAGING-PATH lock.
type StagingManager struct {
	basePath string
}

// NewStagingManager returns a StagingManager rooted at basePath.
// Returns an error when basePath is empty rather than silently
// defaulting — the caller (worker wiring; per-tool runner
// construction) is expected to resolve the env-var-with-fallback
// upstream so the failure mode is visible.
func NewStagingManager(basePath string) (*StagingManager, error) {
	if basePath == "" {
		return nil, errors.New(
			"source.NewStagingManager: basePath required",
		)
	}
	return &StagingManager{basePath: basePath}, nil
}

// StagingDirForScan returns the host-side absolute path where the
// scan's clone should live. Returns an error when scanID is empty
// (must be caller-validated; defensive belt-and-braces here).
func (s *StagingManager) StagingDirForScan(scanID string) (string, error) {
	if scanID == "" {
		return "", errors.New(
			"source.StagingManager.StagingDirForScan: scanID required",
		)
	}
	return filepath.Join(s.basePath, scanID), nil
}

// Cleanup removes the per-scan staging tree. Idempotent: a missing
// directory is not an error. ReadOnly mount inside the container
// does NOT block this host-side rm (the mount is enforced at the
// container kernel namespace boundary; the host filesystem itself
// is read-write).
func (s *StagingManager) Cleanup(scanID string) error {
	dir, err := s.StagingDirForScan(scanID)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf(
			"source.StagingManager.Cleanup: rm %q: %w", dir, err,
		)
	}
	return nil
}
