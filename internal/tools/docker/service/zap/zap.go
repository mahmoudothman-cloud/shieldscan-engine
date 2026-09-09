// Package zap provides the ZAP DAST consumer for the Task 7.5b
// DockerServiceRunner framework (commit 1306ca8).
//
// ZAP is the first DockerServiceRunner consumer; ships with
// cfg.EphemeralContainer = true v1 default per Task 7.5b V4 Option γ
// (newSession cleanup contract verification deferred to Task 7.5c).
//
// Two scan modes (per Task 7.3 design doc Q1+Q2):
//   - Mode B (Spider + Passive Scan) — Quick pricing tier; ~10-20min
//   - Mode C (Spider + Active Scan) — Full pricing tier; ~30min-2h
//
// Authenticated scanning v1: cookie pass-through via ZAP /JSON/httpSessions/
// when target.AuthConfig.Type = "cookie". ExtraArgs zap.auth.* escape
// hatch for form-based power-users; v2 typed enum migration forward-pinned.
//
// Cross-references:
//   - shieldscan-docs commit 682cfcc (Task 7.3 design doc)
//   - shieldscan-docs commit e98a8e4 (Task 7.3 implementation plan)
//   - shieldscan-engine commit 1306ca8 (Task 7.5b framework)
//   - SPECIFICATION.md §13 ADR-026 (DockerServiceRunner architecture)
//   - SPECIFICATION.md §13 ADR-027 (RawFinding.Metadata schema)
//   - SPECIFICATION.md §7.1 (auth block wire schema)
package zap

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/odyssey/shieldscan-engine/internal/events"
	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/odyssey/shieldscan-engine/internal/tools/docker"
	"github.com/odyssey/shieldscan-engine/internal/tools/docker/service"
	"github.com/rs/zerolog"
)

// Image is the canonical ZAP container image with multi-arch digest pin.
// Per ADR-006 risk #14 image-pinning pattern + Phase 0 V1 resolution.
// Resolves to ZAP 2.17.0 (verified at Phase 0 against
// /JSON/core/view/version/?apikey=... endpoint).
const Image = "ghcr.io/zaproxy/zaproxy@sha256:8770b23f9e8b49038f413cb2b10c58c901e5b6717be221a22b1bcab5c9771b8a"

// ContainerPort is the ZAP daemon listen port inside the container.
const ContainerPort = 8080

// ScanMode selects between Mode B (Spider + Passive Scan; Quick tier)
// and Mode C (Spider + Active Scan; Full tier). Maps from
// tools.ScanConfig.Depth via Q4 lock: "quick"→ScanModeQuick;
// "standard"|"deep"→ScanModeFull.
type ScanMode int

const (
	// ScanModeQuick — Mode B: Spider + Passive Scan. Lighter; ~10-20min;
	// Quick pricing tier per SPEC §9.1.
	ScanModeQuick ScanMode = iota
	// ScanModeFull — Mode C: Spider + Active Scan. Comprehensive; ~30min-2h;
	// Full pricing tier per SPEC §9.1.
	ScanModeFull
)

// Config carries the ZAP-consumer-specific tunables passed to
// NewBuildScan and NewRunner.
//
// Per-scan dynamic tuning (mode selection, spider depth, scan policy,
// auth) is NOT in Config — those derive at scan-time from the
// tools.ScanConfig + tools.Target the runner receives:
//   - Mode (Quick=B / Full=C) ← scanModeFor(scanCfg.Depth) per Q1+Q2
//   - Spider knobs (depth, duration, children, threads)
//     ← spiderConfigFor(scanCfg.Depth, scanCfg.MaxRPS) per Q4
//   - Active scan policy ← scanCfg.ExtraArgs["zap.scan_policy"]
//     allowlist-validated against the 22 ZAP-built-in policies
//     enumerated in zapPolicyAllowlist (Phase 0 V5/V17) per Q5
//   - Auth (cookie path) ← target.AuthConfig.Type == "cookie" + Data
//     per Q6 cookie-only v1 lock; ExtraArgs zap.auth.* escape hatch
//     for form-based power-users (v2 typed-enum migration forward-pin)
//
// Config thus carries only static, consumer-injected values. The
// orchestrator wires APIKey at runtime; ZAP daemon must be started
// with -config api.key=<APIKey> per Phase 0 V2 lock.
type Config struct {
	// APIKey is the ZAP daemon API key (set via -config api.key=...
	// at container startup). Empty APIKey is rejected by NewBuildScan
	// at scan-time. Required.
	APIKey string
}

// NewBuildScan returns the BuildScan closure for
// service.DockerServiceRunner.BuildScan field. The closure composes
// target validation → auth setup → spider → mode-specific finalization
// → alert fetch → parse → return RawFindings per design doc §3.3
// lifecycle flow.
//
// Identity-field enrichment (ToolName, EngineCategory, DiscoveredAt,
// Fingerprint) handled by service.DockerServiceRunner.Run loop per
// Task 7.5b service.go pattern; NewBuildScan returns RawFindings with
// Title/Severity/Description/etc. populated.
func NewBuildScan(cfg Config) func(context.Context, tools.Target, tools.ScanConfig, *service.Client) ([]events.RawFinding, error) {
	return func(ctx context.Context, target tools.Target, scanCfg tools.ScanConfig, client *service.Client) ([]events.RawFinding, error) {
		if cfg.APIKey == "" {
			return nil, errors.New("zap: APIKey required (configure ZAP container with -config api.key=...)")
		}
		// (a) Target validation per Q9.
		if err := validateTarget(target.URL, scanCfg.AllowPrivateTargets); err != nil {
			return nil, err
		}

		// (b) Auth setup per Q6 cookie pass-through path. ExtraArgs
		// zap.auth.* form-based escape hatch surfaces but is consumed
		// inline by spider/ascan via runtime configuration; v1 cookie
		// path is the canonical implementation here.
		if target.AuthConfig != nil && target.AuthConfig.Type == "cookie" {
			if _, err := applyCookieAuth(ctx, client, target.URL, target.AuthConfig.Data); err != nil {
				return nil, fmt.Errorf("zap: cookie auth setup: %w", err)
			}
		}
		// v1 form-based escape-hatch surfaces zap.auth.* ExtraArgs keys
		// but is not yet wired (Q6 v2 typed-enum migration forward-pin).
		// Log presence so power-users get visible feedback their config
		// was received but is not yet enforced.
		if extraAuth := extraArgsAuthMap(scanCfg); len(extraAuth) > 0 {
			client.Log.Warn().
				Int("extra_auth_keys", len(extraAuth)).
				Msg("zap: cfg.ExtraArgs zap.auth.* keys present but form-based auth not yet implemented (v2 forward-pin)")
		}

		mode := scanModeFor(scanCfg.Depth)
		sc := spiderConfigFor(scanCfg.Depth, scanCfg.MaxRPS)

		// (c) Spider scan per Q4 lock.
		if _, err := runSpider(ctx, client, target.URL, sc); err != nil {
			return nil, err
		}

		switch mode {
		case ScanModeQuick:
			// (d) Mode B — wait for passive scan queue drain.
			if err := waitForPassiveScanDrain(ctx, client, sc.maxDuration); err != nil {
				return nil, err
			}
		case ScanModeFull:
			// (e) Mode C — also run active scan.
			ac := ascanConfig{
				scanPolicyName: scanCfg.ExtraArgs["zap.scan_policy"],
				maxDuration:    ascanDuration(scanCfg.Depth),
			}
			if _, err := runActiveScan(ctx, client, target.URL, ac); err != nil {
				return nil, err
			}
		}

		// (f)+(g) Bulk fetch alerts + parse to RawFindings.
		alerts, err := fetchAlerts(ctx, client, target.URL)
		if err != nil {
			return nil, err
		}
		return parseAlerts(alerts, target.URL), nil
	}
}

// scanModeFor maps tools.ScanConfig.Depth to ScanMode per Q1+Q2 lock.
// Empty/unknown depth defaults to ScanModeQuick (safest default; lower
// duration; lower resource usage; lower cost-per-scan).
func scanModeFor(depth string) ScanMode {
	switch depth {
	case "standard", "deep":
		return ScanModeFull
	default:
		return ScanModeQuick
	}
}

// NewRunner constructs the DockerServiceRunner consumer wiring per
// Task 7.5b framework + Task 7.3 Q1-Q9 locks + V4 ephemeral default.
// Symmetric with internal/tools/docker/nmap.NewRunner pattern.
// workerID is stamped onto the ephemeral container so a ZAP container
// this process leaves behind on a SIGKILL is reapable by the next
// worker's startup sweep — reaping keys on the label and nothing else,
// so an unlabelled container leaks permanently. Empty is legal and means
// unlabelled (the pre-existing behaviour), which the tests use.
func NewRunner(cli docker.DockerClient, workerID string, cfg Config, log zerolog.Logger) *service.DockerServiceRunner {
	zapLog := log.With().Str("tool", "zap").Logger()
	var labels map[string]string
	if workerID != "" {
		labels = docker.PoolLabels(workerID, "zap")
	}
	return &service.DockerServiceRunner{
		ToolName:     "zap",
		ToolCategory: "dast",
		Cli:          cli,
		ServiceConfig: service.ServiceConfig{
			Image:              Image,
			ContainerPort:      ContainerPort,
			Labels:             labels,
			EphemeralContainer: true, // V4 Option γ default
			ReadinessEndpoint:  "/JSON/core/view/version/?apikey=" + cfg.APIKey,
			AuthFunc:           zapQueryParamAuth(cfg.APIKey),
			// ZAP serves its control API on the SAME port as its forward
			// proxy, so a direct GET to the mapped port returns 502. Every
			// ZAP API call (readiness + spider + ascan + alerts) must be
			// routed THROUGH the mapped port as a proxy, targeting the magic
			// host "zap" — see serviceAddressing. Verified live against ZAP
			// 2.17.0 (direct 502 vs proxied 200).
			APIProxyHost: "zap",
			// Cold boot took ~45-60s+ to answer in early live testing, so
			// this was set well over the 120s framework default. With
			// -silent (below) a cold start is ~15s; the margin is left
			// generous because the readiness poll now aborts as soon as the
			// container dies rather than sitting out the full window, so a
			// long timeout no longer costs four minutes to learn nothing.
			ReadinessTimeout: 240 * time.Second,
			// Launch the ZAP daemon with the SAME api.key the client uses, so
			// the control-API handshake succeeds. api.addrs.* opens the API to
			// non-localhost callers (the mapped host port looks non-local to
			// ZAP); safe because spinup binds the host port to 127.0.0.1 only.
			// Exact daemon flags are verified live (see the wiring plan's
			// reality-check); the api.key here is the load-bearing part.
			//
			// -silent disables ZAP's check-for-update on startup, and it
			// is a reproducibility fix, not a tuning knob. Image is pinned
			// by digest — and then every cold start reaches the internet
			// and installs a fresh set of ~30 add-ons over the top of it
			// (observed: "Installing new addon ascanrules v83.0.0" followed
			// by 30 "Add-on downloaded to:" lines). So the digest pin does
			// not determine what actually runs: two scans a week apart
			// execute different rules, and a rule set changing under us is
			// invisible in every artefact we keep. It also puts a
			// mandatory, network-dependent download on the critical path of
			// every single scan, which is the leading suspect for the ZAP
			// container that died 34s into boot. Measured: -silent prints
			// "Shh! No check-for-update - silent mode enabled", downloads
			// nothing, and is listening in ~15s instead of ~21s.
			//
			// The consequence to accept: add-on currency now requires a
			// deliberate image bump rather than happening by itself. That
			// is the intended trade — see VERSIONS.md for the pin.
			Cmd: []string{
				"zap.sh", "-daemon", "-silent",
				"-host", "0.0.0.0",
				"-port", fmt.Sprintf("%d", ContainerPort),
				"-config", "api.key=" + cfg.APIKey,
				"-config", "api.addrs.addr.name=.*",
				"-config", "api.addrs.addr.regex=true",
			},
		},
		BuildScan: NewBuildScan(cfg),
		Log:       zapLog,
	}
}
