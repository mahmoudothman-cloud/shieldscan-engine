package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/rs/zerolog"

	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/odyssey/shieldscan-engine/internal/tools/checkov"
	"github.com/odyssey/shieldscan-engine/internal/tools/corstest"
	"github.com/odyssey/shieldscan-engine/internal/tools/depcheck"
	"github.com/odyssey/shieldscan-engine/internal/tools/gitleaks"
	"github.com/odyssey/shieldscan-engine/internal/tools/nikto"
	"github.com/odyssey/shieldscan-engine/internal/tools/nuclei"
	"github.com/odyssey/shieldscan-engine/internal/tools/semgrep"
	"github.com/odyssey/shieldscan-engine/internal/tools/sslyze"
	"github.com/odyssey/shieldscan-engine/internal/tools/wapiti"
	"github.com/odyssey/shieldscan-engine/internal/worker"
)

// nucleiDefaultRPS is the rate-limit fallback when ScanConfig.MaxRPS
// is zero. Per plan §6.1 (Nuclei) + nuclei.Config.DefaultRPS docs;
// pinned here so M6.8 wiring is the single source of truth for the
// runtime default. Operators tune at job-dispatch time via
// ScanConfig.MaxRPS.
const nucleiDefaultRPS = 50

// buildRegistry resolves binary paths for the 9 M6 native ToolRunners
// and constructs the worker.Registry + the matching []NativeBinary
// list for Phase 1 startup verification.
//
// Tool listing (alphabetical — matches DRIFT-LOG entry 4 ordering):
//
//	checkov   sast → IaC config scanner
//	corstest  api  → CORS misconfiguration probe
//	depcheck  sca  → OWASP Dependency-Check
//	gitleaks  secrets → git-history secret scan
//	nikto     dast → web server vulnerability scanner
//	nuclei    dast → CVE/template-driven scanner
//	semgrep   sast → static-analysis (per-rule)
//	sslyze    ssl  → TLS/SSL configuration probe
//	wapiti    dast → web vulnerability scanner
//
// Recon helpers (Subfinder + httpx) are intentionally NOT registered
// here per ADR-022: they're pre-scan helpers (target discovery), not
// ToolRunners (their output is target-discovery data, not
// events.RawFinding). M8 (Recon-First Pipeline) imports
// internal/tools/recon and invokes recon.RunRecon directly as a
// pre-scan phase before per-target scan jobs are dispatched here.
//
// Binary resolution applies DEVELOPMENT-PATTERNS Pattern 2 via
// resolveBinary(): SHIELDSCAN_<TOOL>_BINARY env first; exec.LookPath
// fallback; fail-fast if both empty. 12 instances of the env-var-
// binary pattern across M6.
//
// Failure semantics: any binary-resolution error is wrapped with the
// failing tool's name and returned. runMain treats this as exit 1
// (startup failure) — operationally preferable to silently
// registering a runner that points at a missing binary.
func buildRegistry(log zerolog.Logger) (map[string]tools.ToolRunner, []worker.NativeBinary, error) {
	// Tool spec drives both registration and Phase 1 NativeBinary list.
	// Defined inline (not as a package-level var) so tests building
	// alternative wiring shapes don't pick up shared mutable state.
	type spec struct {
		envVar   string // SHIELDSCAN_<TOOL>_BINARY
		toolName string // exec.LookPath fallback name
		engine   string // worker.Registry key
	}
	specs := []spec{
		{"SHIELDSCAN_CHECKOV_BINARY", "checkov", "checkov"},
		{"SHIELDSCAN_CORSTEST_BINARY", "corstest", "corstest"},
		{"SHIELDSCAN_DEPCHECK_BINARY", "dependency-check.sh", "depcheck"},
		{"SHIELDSCAN_GITLEAKS_BINARY", "gitleaks", "gitleaks"},
		{"SHIELDSCAN_NIKTO_BINARY", "nikto", "nikto"},
		{"SHIELDSCAN_NUCLEI_BINARY", "nuclei", "nuclei"},
		{"SHIELDSCAN_SEMGREP_BINARY", "semgrep", "semgrep"},
		{"SHIELDSCAN_SSLYZE_BINARY", "sslyze", "sslyze"},
		{"SHIELDSCAN_WAPITI_BINARY", "wapiti", "wapiti"},
	}

	paths := make(map[string]string, len(specs))
	natives := make([]worker.NativeBinary, 0, len(specs))
	for _, s := range specs {
		path, err := resolveBinary(s.envVar, s.toolName)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve %s binary: %w", s.engine, err)
		}
		paths[s.engine] = path
		natives = append(natives, worker.NativeBinary{Name: s.engine, Path: path})
	}

	// Nuclei needs an additional resource: the templates directory.
	// Resolved from SHIELDSCAN_NUCLEI_TEMPLATES env (Pattern 2 sibling)
	// or default to "$HOME/nuclei-templates" — the canonical path that
	// `nuclei -update-templates` writes to.
	templatesDir := os.Getenv("SHIELDSCAN_NUCLEI_TEMPLATES")
	if templatesDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, nil, fmt.Errorf("resolve nuclei templates dir: %w", err)
		}
		templatesDir = filepath.Join(home, "nuclei-templates")
	}

	runners := map[string]tools.ToolRunner{
		"checkov":  checkov.NewCheckovRunner(checkov.Config{BinaryPath: paths["checkov"]}, log),
		"corstest": corstest.NewCORStestRunner(corstest.Config{BinaryPath: paths["corstest"]}, log),
		"depcheck": depcheck.NewDepCheckRunner(depcheck.Config{BinaryPath: paths["depcheck"]}, log),
		"gitleaks": gitleaks.NewGitleaksRunner(gitleaks.Config{BinaryPath: paths["gitleaks"]}, log),
		// TLSCapable is opt-in: apt's Nikto 2.1.5 cannot scan an HTTPS
		// target and silently reports the server's plain-HTTP error page
		// instead. Set SHIELDSCAN_NIKTO_TLS_CAPABLE=1 only after
		// verifying a newer binary against a real HTTPS target.
		"nikto": nikto.NewNiktoRunner(nikto.Config{
			BinaryPath: paths["nikto"],
			TLSCapable: envEnabled("SHIELDSCAN_NIKTO_TLS_CAPABLE"),
		}, log),
		"nuclei": nuclei.NewNucleiRunner(nuclei.Config{
			BinaryPath:   paths["nuclei"],
			TemplatesDir: templatesDir,
			DefaultRPS:   nucleiDefaultRPS,
		}, log),
		"semgrep": semgrep.NewSemgrepRunner(semgrep.Config{BinaryPath: paths["semgrep"]}, log),
		"sslyze":  sslyze.NewSSLyzeRunner(sslyze.Config{BinaryPath: paths["sslyze"]}, log),
		"wapiti":  wapiti.NewWapitiRunner(wapiti.Config{BinaryPath: paths["wapiti"]}, log),
	}

	return runners, natives, nil
}
