package mobsf

import (
	"errors"
	"fmt"
	"path"
	"strings"
)

// Platform values per Q2(iv) lock. Maps from target.MobileOS-like
// schemas via JobMobileConfig.Platform (events.JobMobileConfig).
const (
	PlatformAndroid = "android"
	PlatformIOS     = "ios"
)

// AnalysisType values per Q2 lock. v1 ships static only; dynamic +
// source-tree return "not implemented v1" errors.
const (
	AnalysisStatic = "static"
)

// androidExtensions are the canonical Android app artifact extensions
// MobSF /api/v1/upload accepts. Phase 0 V2: APK + XAPK + AAB.
var androidExtensions = map[string]struct{}{
	".apk":  {},
	".xapk": {},
	".aab":  {},
}

// iosExtensions are the canonical iOS app artifact extensions MobSF
// /api/v1/upload accepts. Phase 0 V2: IPA.
var iosExtensions = map[string]struct{}{
	".ipa": {},
}

// mobileTarget bundles validated mobile-job fields. Constructed via
// validateMobileTarget from tools.Target + events.JobMobileConfig
// equivalents.
type mobileTarget struct {
	UploadRef    string // r2://bucket/key form
	Platform     string // PlatformAndroid | PlatformIOS
	AnalysisType string // AnalysisStatic (v1)
	FileName     string // basename of UploadRef (e.g., "diva-beta.apk")
}

// validateMobileTarget enforces Q2(iv) file-extension + platform
// invariants and the v1-static-only AnalysisType lock. Returns
// errors with structured messages suitable for orchestrator surfacing.
//
// Per Q2(iv): platform=android requires .apk/.xapk/.aab; platform=ios
// requires .ipa. Cross-platform mismatch (e.g., .apk under ios) is
// rejected pre-upload to avoid wasting MobSF analyser time.
func validateMobileTarget(uploadRef, platform, analysisType string) (mobileTarget, error) {
	mt := mobileTarget{
		UploadRef:    uploadRef,
		Platform:     platform,
		AnalysisType: analysisType,
	}

	if uploadRef == "" {
		return mt, errors.New("mobsf: MobileUploadRef required")
	}
	if !strings.HasPrefix(uploadRef, "r2://") {
		return mt, fmt.Errorf("mobsf: MobileUploadRef must use r2:// scheme; got %q", uploadRef)
	}
	mt.FileName = path.Base(strings.TrimPrefix(uploadRef, "r2://"))
	if mt.FileName == "" || mt.FileName == "." || mt.FileName == "/" {
		return mt, fmt.Errorf("mobsf: MobileUploadRef has empty basename: %q", uploadRef)
	}

	switch platform {
	case PlatformAndroid, PlatformIOS:
		// ok
	case "":
		return mt, errors.New("mobsf: platform required (android|ios)")
	default:
		return mt, fmt.Errorf("mobsf: platform %q not supported (android|ios)", platform)
	}

	switch analysisType {
	case AnalysisStatic:
		// ok
	case "":
		return mt, errors.New("mobsf: analysis_type required (static)")
	case "dynamic", "source":
		return mt, fmt.Errorf("mobsf: analysis_type %q not implemented v1 (forward-pin)", analysisType)
	default:
		return mt, fmt.Errorf("mobsf: analysis_type %q not supported", analysisType)
	}

	if err := validateFileExtension(mt.FileName, platform); err != nil {
		return mt, err
	}
	return mt, nil
}

// validateFileExtension cross-checks basename extension against the
// platform's allowlist per Q2(iv) lock.
func validateFileExtension(fileName, platform string) error {
	ext := strings.ToLower(path.Ext(fileName))
	switch platform {
	case PlatformAndroid:
		if _, ok := androidExtensions[ext]; !ok {
			return fmt.Errorf("mobsf: android platform requires .apk/.xapk/.aab; got %q", ext)
		}
	case PlatformIOS:
		if _, ok := iosExtensions[ext]; !ok {
			return fmt.Errorf("mobsf: ios platform requires .ipa; got %q", ext)
		}
	}
	return nil
}
