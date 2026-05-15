package mobsf

import (
	"strings"
	"testing"
)

func TestValidateMobileTarget(t *testing.T) {
	cases := []struct {
		name         string
		uploadRef    string
		platform     string
		analysisType string
		wantErr      string // substring; empty = expect no error
	}{
		{"happy android apk", "r2://uploads/org/diva.apk", "android", "static", ""},
		{"happy ios ipa", "r2://uploads/org/app.ipa", "ios", "static", ""},
		{"happy aab", "r2://uploads/x/app.aab", "android", "static", ""},
		{"happy xapk", "r2://uploads/x/app.xapk", "android", "static", ""},

		{"empty ref", "", "android", "static", "MobileUploadRef required"},
		{"bad scheme", "s3://x/y", "android", "static", "r2:// scheme"},
		{"empty basename", "r2://", "android", "static", "empty basename"},

		{"missing platform", "r2://u/x.apk", "", "static", "platform required"},
		{"bad platform", "r2://u/x.apk", "win", "static", "not supported"},

		{"missing analysis", "r2://u/x.apk", "android", "", "analysis_type required"},
		{"dynamic forward-pin", "r2://u/x.apk", "android", "dynamic", "not implemented v1"},
		{"source forward-pin", "r2://u/x.apk", "android", "source", "not implemented v1"},
		{"bad analysis", "r2://u/x.apk", "android", "exotic", "not supported"},

		{"android wrong ext (ipa)", "r2://u/x.ipa", "android", "static", "android platform requires"},
		{"ios wrong ext (apk)", "r2://u/x.apk", "ios", "static", "ios platform requires"},
		{"android no ext", "r2://u/x", "android", "static", "android platform requires"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := validateMobileTarget(c.uploadRef, c.platform, c.analysisType)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("expected nil err; got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q; got nil", c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("error %q missing substring %q", err.Error(), c.wantErr)
			}
		})
	}
}

func TestValidateMobileTarget_FileNameExtraction(t *testing.T) {
	mt, err := validateMobileTarget("r2://bucket/path/to/diva-beta.apk", "android", "static")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mt.FileName != "diva-beta.apk" {
		t.Fatalf("expected FileName=diva-beta.apk; got %q", mt.FileName)
	}
}

func TestValidateFileExtension_CaseInsensitive(t *testing.T) {
	if err := validateFileExtension("App.APK", PlatformAndroid); err != nil {
		t.Fatalf("upper-case .APK should be accepted; got %v", err)
	}
	if err := validateFileExtension("App.IPA", PlatformIOS); err != nil {
		t.Fatalf("upper-case .IPA should be accepted; got %v", err)
	}
}
