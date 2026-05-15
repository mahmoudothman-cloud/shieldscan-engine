package mobsf

import (
	"strings"
	"testing"
)

func TestNewR2Fetcher_Validation(t *testing.T) {
	if _, err := newR2Fetcher(R2Config{}, noopLog()); err == nil {
		t.Fatal("expected error on empty Endpoint")
	}
	if _, err := newR2Fetcher(R2Config{Endpoint: "https://x"}, noopLog()); err == nil {
		t.Fatal("expected error on empty credentials")
	}
	if _, err := newR2Fetcher(R2Config{
		Endpoint:        "https://example.com",
		AccessKeyID:     "k",
		SecretAccessKey: "s",
		Bucket:          "b",
	}, noopLog()); err != nil {
		t.Fatalf("happy newR2Fetcher: %v", err)
	}
}

func TestResolveRef(t *testing.T) {
	f := &s3R2Fetcher{cfg: R2Config{Bucket: "default-bucket"}}
	cases := []struct {
		ref        string
		wantBucket string
		wantKey    string
		wantErr    string
	}{
		{"r2://bucket1/path/to/file.apk", "bucket1", "path/to/file.apk", ""},
		{"r2://justkey.apk", "default-bucket", "justkey.apk", ""},
		{"", "", "", "r2:// scheme"},
		{"r2://", "", "", "empty after r2://"},
		{"s3://x/y", "", "", "r2:// scheme"},
	}
	for _, c := range cases {
		t.Run(c.ref, func(t *testing.T) {
			b, k, err := f.resolveRef(c.ref)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("expected err containing %q; got %v", c.wantErr, err)
				}
				return
			}
			if b != c.wantBucket || k != c.wantKey {
				t.Fatalf("got (%s,%s); want (%s,%s)", b, k, c.wantBucket, c.wantKey)
			}
		})
	}
}

func TestResolveRef_NoDefaultBucket(t *testing.T) {
	f := &s3R2Fetcher{cfg: R2Config{}}
	_, _, err := f.resolveRef("r2://justkey.apk")
	if err == nil || !strings.Contains(err.Error(), "no embedded bucket") {
		t.Fatalf("expected no-embedded-bucket error; got %v", err)
	}
}
