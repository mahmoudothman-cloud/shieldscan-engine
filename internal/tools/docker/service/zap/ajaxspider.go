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

// AJAX spider (browser-driven crawl) — Benchmark 2026-11-16, DRIFT-LOG.
//
// The classic spider parses HTML; on a single-page application it sees
// one page and a bundle, so the REST endpoints the app's JavaScript
// calls (/rest/..., /api/...) are never discovered and the active scan
// has nothing to inject into. A standalone `zap-full-scan.py -j` found
// SQL injection on Juice Shop; the engine's spider-only crawl found
// headers. Full mode now runs the AJAX spider after the classic one
// and before the active scan. Quick mode (passive) does not — the
// browser crawl is the expensive part.
//
// Failure is tolerated: the AJAX spider needs a headless browser inside
// the container; if the add-on or browser is missing the classic
// spider's results still get an active scan, and the warning says why
// coverage is thinner.

// ajaxSpiderDuration bounds the browser crawl per depth. The standalone
// benchmark used 15 min; "standard" gets 8 so a scan with several
// recon-discovered hosts stays inside its lease.
func ajaxSpiderDuration(depth string) time.Duration {
	switch depth {
	case "deep":
		return 15 * time.Minute
	default:
		return 8 * time.Minute
	}
}

// runAjaxSpider starts the AJAX spider on targetURL, bounded by
// maxDuration, and waits for it to stop. Returns the number of URLs it
// found (0 on failure, with the error).
func runAjaxSpider(ctx context.Context, client *service.Client, targetURL string, maxDuration time.Duration) (int, error) {
	minutes := int(maxDuration / time.Minute)
	if minutes < 1 {
		minutes = 1
	}
	if _, err := client.Get(ctx, "/JSON/ajaxSpider/action/setOptionMaxDuration/?Integer="+strconv.Itoa(minutes)); err != nil {
		return 0, fmt.Errorf("zap ajaxspider: set max duration: %w", err)
	}
	q := url.Values{}
	q.Set("url", targetURL)
	q.Set("inScope", "false")
	q.Set("subtreeOnly", "true")
	body, err := client.Get(ctx, "/JSON/ajaxSpider/action/scan/?"+q.Encode())
	if err != nil {
		return 0, fmt.Errorf("zap ajaxspider: action/scan: %w", err)
	}
	var started struct {
		Result string `json:"Result"`
	}
	if err := json.Unmarshal(body, &started); err != nil || started.Result != "OK" {
		return 0, fmt.Errorf("zap ajaxspider: scan not accepted: %s", string(body))
	}
	pollOpts := service.PollOpts{
		InitialInterval: 3 * time.Second,
		MaxInterval:     15 * time.Second,
		MaxAttempts:     400,
		// The spider stops itself at maxDuration; give the poll a little
		// more so a late "stopped" is still seen.
		MaxDuration: maxDuration + time.Minute,
	}
	if _, err := client.PollUntil(ctx, "/JSON/ajaxSpider/view/status/", ajaxSpiderStoppedPredicate, pollOpts); err != nil {
		// Make sure the browser crawl is not left running under the
		// active scan on a poll timeout.
		_, _ = client.Get(ctx, "/JSON/ajaxSpider/action/stop/")
		return 0, fmt.Errorf("zap ajaxspider: poll status: %w", err)
	}
	countBody, err := client.Get(ctx, "/JSON/ajaxSpider/view/numberOfResults/")
	if err != nil {
		return 0, nil // crawl happened; the count is only for the log
	}
	var count struct {
		NumberOfResults string `json:"numberOfResults"`
	}
	_ = json.Unmarshal(countBody, &count)
	n, _ := strconv.Atoi(count.NumberOfResults)
	return n, nil
}

// ajaxSpiderStoppedPredicate: /JSON/ajaxSpider/view/status/ reports
// "running" while crawling and "stopped" when done (or never started).
func ajaxSpiderStoppedPredicate(body []byte) (bool, error) {
	var resp struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return false, fmt.Errorf("parse status: %w", err)
	}
	return resp.Status == "stopped", nil
}
