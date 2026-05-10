package zap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/odyssey/shieldscan-engine/internal/tools/docker/service"
)

// zapPolicyAllowlist is the canonical set of ZAP scan policy names
// accepted in cfg.ExtraArgs["zap.scan_policy"]. Per Phase 0 V5/V17
// finding: ZAP 2.17.0 at pinned digest sha256:8770b... ships 22
// policies (NOT the 9 named in pre-Phase-0 documentation reads).
//
// Source: empirical /JSON/ascan/view/scanPolicyNames/?apikey= query
// against pinned digest. Strings preserved verbatim including casing
// and whitespace. Drift from documentation captured here for Phase 5.A
// design-doc revision target.
//
// Default v1 omits scanPolicyName parameter from /JSON/ascan/action/scan/
// (ZAP runs Default Policy implicitly). Allowlist only consulted when
// tenant power-user supplies cfg.ExtraArgs["zap.scan_policy"].
var zapPolicyAllowlist = map[string]struct{}{
	"API":             {},
	"API-Minimal":     {},
	"Default Policy":  {},
	"Dev CICD":        {},
	"Dev Full":        {},
	"Dev Standard":    {},
	"Pen Test":        {},
	"QA CICD":         {},
	"QA Full":         {},
	"QA Standard":     {},
	"Sequence":        {},
	"St-High-Th-High": {},
	"St-High-Th-Low":  {},
	"St-High-Th-Med":  {},
	"St-Ins-Th-High":  {},
	"St-Ins-Th-Low":   {},
	"St-Ins-Th-Med":   {},
	"St-Low-Th-High":  {},
	"St-Low-Th-Low":   {},
	"St-Low-Th-Med":   {},
	"St-Med-Th-High":  {},
	"St-Med-Th-Low":   {},
}

// validateScanPolicy returns nil if the name is empty (use Default
// Policy implicitly) or in the allowlist; otherwise returns a
// validation error naming the rejection.
func validateScanPolicy(name string) error {
	if name == "" {
		return nil
	}
	if _, ok := zapPolicyAllowlist[name]; !ok {
		return fmt.Errorf("zap ascan: scan policy %q not in allowlist (22 ZAP-built-in policies; see internal/tools/docker/service/zap/ascan.go zapPolicyAllowlist)", name)
	}
	return nil
}

// ascanConfig captures the per-Mode-C active scan parameters surfaced
// in design doc Q5/Q9 lock. Mode B does not invoke ascan; only Mode C
// (Full pricing tier) runs active scan.
type ascanConfig struct {
	scanPolicyName string        // empty = Default Policy
	maxDuration    time.Duration // ctx-driven cap
}

// runActiveScan triggers ZAP active scan against the target URL,
// optionally with a non-default scan policy from the allowlist, and
// waits for completion. Per design doc §3.3 step (e) — POST
// /JSON/ascan/action/scan/ + PollUntil /JSON/ascan/view/status/.
//
// Active scan generates alerts via attack payloads against discovered
// URLs from the prior spider phase; its duration is bounded by ZAP's
// internal queues and the maxDuration timeout (caller's ctx-derived).
func runActiveScan(ctx context.Context, client *service.Client, targetURL string, ac ascanConfig) (string, error) {
	if err := validateScanPolicy(ac.scanPolicyName); err != nil {
		return "", err
	}
	q := url.Values{}
	q.Set("url", targetURL)
	if ac.scanPolicyName != "" {
		q.Set("scanPolicyName", ac.scanPolicyName)
	}
	scanPath := "/JSON/ascan/action/scan/?" + q.Encode()
	body, err := client.Get(ctx, scanPath)
	if err != nil {
		return "", fmt.Errorf("zap ascan: action/scan: %w", err)
	}
	var scanResp struct {
		Scan string `json:"scan"`
	}
	if err := json.Unmarshal(body, &scanResp); err != nil {
		return "", fmt.Errorf("zap ascan: parse scan response: %w", err)
	}
	if scanResp.Scan == "" {
		return "", fmt.Errorf("zap ascan: empty scan ID")
	}

	statusPath := "/JSON/ascan/view/status/?scanId=" + scanResp.Scan
	pollOpts := service.PollOpts{
		InitialInterval: 5 * time.Second,
		MaxInterval:     30 * time.Second,
		MaxAttempts:     1000,
		MaxDuration:     ac.maxDuration,
	}
	predicate := func(body []byte) (bool, error) {
		var resp struct {
			Status string `json:"status"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return false, fmt.Errorf("parse ascan status: %w", err)
		}
		return resp.Status == "100", nil
	}
	if _, err := client.PollUntil(ctx, statusPath, predicate, pollOpts); err != nil {
		// Best-effort stop on timeout; framework swallows error since
		// findings may still be partially recoverable.
		_, _ = client.Get(ctx, "/JSON/ascan/action/stop/?scanId="+scanResp.Scan)
		return scanResp.Scan, fmt.Errorf("zap ascan: poll status: %w", err)
	}
	return scanResp.Scan, nil
}

// ascanDuration maps tools.ScanConfig.Depth to active scan max
// duration. Mode C is the canonical Full-tier shape; quick-Mode-C
// is uncommon (Mode B preferred for quick) but supported.
func ascanDuration(depth string) time.Duration {
	switch depth {
	case "quick":
		return 10 * time.Minute
	case "deep":
		return 90 * time.Minute
	default:
		return 30 * time.Minute
	}
}
