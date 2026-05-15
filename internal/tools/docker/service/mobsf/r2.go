package mobsf

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/rs/zerolog"
)

// R2Config carries the Cloudflare R2 (S3-compatible) credentials +
// endpoint required to fetch a MobileUploadRef binary to worker-local
// staging. Per Task 7.4 design doc §3.3 R2 path.
//
// Naming aligns with internal/config/config.go SHIELDSCAN_R2_* env
// scheme (Endpoint instead of AccountID; matches existing engine-side
// pattern). The implementation plan referenced R2_ACCOUNT_ID/etc.
// generic envs — surfaced as DEVIATION (see Phase 1 surface report).
type R2Config struct {
	// Endpoint is the R2 S3-compatible URL (e.g.,
	// https://<account-id>.r2.cloudflarestorage.com). Required.
	Endpoint string
	// AccessKeyID + SecretAccessKey are the R2 API token pair. Required.
	AccessKeyID     string
	SecretAccessKey string
	// Bucket is the R2 bucket name. Used when MobileUploadRef does NOT
	// embed a bucket (form: r2://uploads/<org>/<file>) — see resolveRef.
	Bucket string
}

// r2Fetcher abstracts the binary download for test fakes; production
// implementation wraps an S3 client.
type r2Fetcher interface {
	Fetch(ctx context.Context, uploadRef string) (localPath string, cleanup func(), err error)
}

// s3R2Fetcher is the production r2Fetcher backed by aws-sdk-go-v2 s3
// with R2-style path-style addressing.
type s3R2Fetcher struct {
	cfg    R2Config
	client *s3.Client
	log    zerolog.Logger
}

// newR2Fetcher constructs the production fetcher. Validates required
// fields early so per-scan failures surface with structured messages.
func newR2Fetcher(cfg R2Config, log zerolog.Logger) (*s3R2Fetcher, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("mobsf r2: R2Config.Endpoint required")
	}
	if cfg.AccessKeyID == "" || cfg.SecretAccessKey == "" {
		return nil, errors.New("mobsf r2: R2Config.AccessKeyID + SecretAccessKey required")
	}
	creds := credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, "")
	client := s3.New(s3.Options{
		Region:       "auto",
		Credentials:  creds,
		BaseEndpoint: aws.String(cfg.Endpoint),
		UsePathStyle: true,
	})
	return &s3R2Fetcher{cfg: cfg, client: client, log: log}, nil
}

// Fetch downloads the binary referenced by uploadRef (r2://<bucket>/<key>
// form; bucket defaults to R2Config.Bucket when not embedded) to a
// worker-local temp file. Returns the local path + a cleanup closure
// that removes the temp file (caller defers).
//
// ctx cancellation propagates to the S3 GetObject call.
func (f *s3R2Fetcher) Fetch(ctx context.Context, uploadRef string) (string, func(), error) {
	bucket, key, err := f.resolveRef(uploadRef)
	if err != nil {
		return "", nil, err
	}

	out, err := f.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return "", nil, fmt.Errorf("mobsf r2: get object %s/%s: %w", bucket, key, err)
	}
	defer func() { _ = out.Body.Close() }()

	// Stage to worker-local /tmp. Preserve the original basename so
	// MobSF /api/v1/upload sees a file with the right extension (Phase
	// 0 V2: extension drives platform/parser routing inside MobSF).
	baseName := path.Base(key)
	tmpDir, err := os.MkdirTemp("", "mobsf-r2-*")
	if err != nil {
		return "", nil, fmt.Errorf("mobsf r2: mkdtemp: %w", err)
	}
	localPath := path.Join(tmpDir, baseName)
	fd, err := os.Create(localPath) //nolint:gosec // localPath rooted in our own MkdirTemp dir
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", nil, fmt.Errorf("mobsf r2: create staging file: %w", err)
	}
	if _, err := io.Copy(fd, out.Body); err != nil {
		_ = fd.Close()
		_ = os.RemoveAll(tmpDir)
		return "", nil, fmt.Errorf("mobsf r2: stream body to %s: %w", localPath, err)
	}
	if err := fd.Close(); err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", nil, fmt.Errorf("mobsf r2: close staging file: %w", err)
	}

	cleanup := func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			f.log.Warn().Err(err).Str("staging_dir", tmpDir).Msg("mobsf r2: staging cleanup failed")
		}
	}
	return localPath, cleanup, nil
}

// resolveRef parses uploadRef into (bucket, key). Supports two forms:
//
//	r2://<bucket>/<key/path>    — bucket embedded in ref
//	r2://<key/path>             — bucket defaulted to R2Config.Bucket
//
// Per Task 7.4 design doc §3.3 R2 staging-path semantics.
func (f *s3R2Fetcher) resolveRef(uploadRef string) (bucket, key string, err error) {
	if !strings.HasPrefix(uploadRef, "r2://") {
		return "", "", fmt.Errorf("mobsf r2: ref %q does not use r2:// scheme", uploadRef)
	}
	body := strings.TrimPrefix(uploadRef, "r2://")
	if body == "" {
		return "", "", fmt.Errorf("mobsf r2: ref %q is empty after r2:// prefix", uploadRef)
	}
	// If a single segment, treat as key under default bucket.
	parts := strings.SplitN(body, "/", 2)
	if len(parts) == 1 {
		if f.cfg.Bucket == "" {
			return "", "", fmt.Errorf("mobsf r2: ref %q has no embedded bucket and R2Config.Bucket is empty", uploadRef)
		}
		return f.cfg.Bucket, parts[0], nil
	}
	// Two-segment form: first = bucket, second = key.
	return parts[0], parts[1], nil
}
