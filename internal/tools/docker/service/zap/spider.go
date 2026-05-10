package zap

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/odyssey/shieldscan-engine/internal/tools/docker/service"
)

// spiderConfig captures the per-Depth ZAP spider knobs surfaced in
// design doc Q4 lock. Mode B + Mode C both run the spider first;
// Mode B then waits for passive scan drain; Mode C additionally runs
// active scan via ascan.go.
type spiderConfig struct {
	maxDepth    int
	maxDuration time.Duration
	maxChildren int
	threadCount int // derived from cfg.MaxRPS
}

// spiderConfigFor maps tools.ScanConfig.Depth to ZAP spider params
// per Q4 lock: quick→3+5min+50; standard→5+10min+200; deep→8+20min+500.
// Empty/unknown depth defaults to "standard".
func spiderConfigFor(depth string, maxRPS int) spiderConfig {
	switch depth {
	case "quick":
		return spiderConfig{maxDepth: 3, maxDuration: 5 * time.Minute, maxChildren: 50, threadCount: capThreadCount(maxRPS, 5)}
	case "deep":
		return spiderConfig{maxDepth: 8, maxDuration: 20 * time.Minute, maxChildren: 500, threadCount: capThreadCount(maxRPS, 20)}
	default:
		return spiderConfig{maxDepth: 5, maxDuration: 10 * time.Minute, maxChildren: 200, threadCount: capThreadCount(maxRPS, 10)}
	}
}

// capThreadCount maps cfg.MaxRPS to ZAP spider ThreadCount with a
// per-mode cap (the cap reflects diminishing returns; spider is I/O
// bound on target latency, not CPU). Zero MaxRPS → mode default.
func capThreadCount(maxRPS, modeDefault int) int {
	if maxRPS <= 0 {
		return modeDefault
	}
	if maxRPS > modeDefault {
		return modeDefault
	}
	return maxRPS
}

// runSpider triggers a ZAP spider scan against the target URL with
// the configured spider parameters and waits for completion. Returns
// the spider scan ID for caller use (e.g., result fetching). If
// authSession is non-empty, includes it in the spider request to
// activate authenticated-context scanning per V18 cookie path.
//
// Per design doc §3.3 step (c) — POST /JSON/spider/action/scan/ +
// PollUntil /JSON/spider/view/status/ via framework Q4 polling.
func runSpider(ctx context.Context, client *service.Client, targetURL string, sc spiderConfig) (string, error) {
	q := url.Values{}
	q.Set("url", targetURL)
	q.Set("maxChildren", strconv.Itoa(sc.maxChildren))
	scanPath := "/JSON/spider/action/scan/?" + q.Encode()
	body, err := client.Get(ctx, scanPath)
	if err != nil {
		return "", fmt.Errorf("zap spider: action/scan: %w", err)
	}
	var scanResp struct {
		Scan string `json:"scan"`
	}
	if err := json.Unmarshal(body, &scanResp); err != nil {
		return "", fmt.Errorf("zap spider: parse scan response: %w", err)
	}
	if scanResp.Scan == "" {
		return "", fmt.Errorf("zap spider: empty scan ID")
	}

	statusPath := "/JSON/spider/view/status/?scanId=" + scanResp.Scan
	pollOpts := service.PollOpts{
		InitialInterval: 2 * time.Second,
		MaxInterval:     15 * time.Second,
		MaxAttempts:     300,
		MaxDuration:     sc.maxDuration,
	}
	if _, err := client.PollUntil(ctx, statusPath, spiderStatusPredicate, pollOpts); err != nil {
		return scanResp.Scan, fmt.Errorf("zap spider: poll status: %w", err)
	}
	return scanResp.Scan, nil
}

// spiderStatusPredicate returns done=true when /JSON/spider/view/status/
// reports 100. ZAP returns status as JSON STRING ("100"), per Phase 0
// V6/V7 string-vs-int drift pattern.
func spiderStatusPredicate(body []byte) (bool, error) {
	var resp struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return false, fmt.Errorf("parse status: %w", err)
	}
	return resp.Status == "100", nil
}

// waitForPassiveScanDrain polls /JSON/pscan/view/recordsToScan/ until
// the queue is empty (returns "0"). Mode B path — passive scan
// implicitly runs alongside spider; finding-fetch must wait for
// completion to capture all alerts.
func waitForPassiveScanDrain(ctx context.Context, client *service.Client, maxDuration time.Duration) error {
	pollOpts := service.PollOpts{
		InitialInterval: 2 * time.Second,
		MaxInterval:     10 * time.Second,
		MaxAttempts:     300,
		MaxDuration:     maxDuration,
	}
	predicate := func(body []byte) (bool, error) {
		var resp struct {
			RecordsToScan string `json:"recordsToScan"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return false, fmt.Errorf("parse recordsToScan: %w", err)
		}
		return resp.RecordsToScan == "0", nil
	}
	if _, err := client.PollUntil(ctx, "/JSON/pscan/view/recordsToScan/", predicate, pollOpts); err != nil {
		return fmt.Errorf("zap spider: passive scan drain: %w", err)
	}
	return nil
}
