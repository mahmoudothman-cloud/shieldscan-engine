package sqlmap

import (
	"github.com/odyssey/shieldscan-engine/internal/tools"
)

// buildArgs produces the CLI argv for SQLMap scans. Output shape:
//
//	sqlmap -u <url> --batch --disable-coloring --level=<N> --risk=<N>
//
// Per Q5 (a) 3-tier ScanConfig.Depth → --level/--risk mapping lock:
//
//	cfg.Depth = "quick" (or default) → --level=1 --risk=1 (~10–15s)
//	cfg.Depth = "standard"           → --level=3 --risk=2 (~30–60s)
//	cfg.Depth = "deep"               → --level=5 --risk=3 (~3–5min)
//
// Per Q9 (a) Target.URL canonical scan target; --batch is mandatory
// automation flag per V3 empirical (sqlmap prompts interactively
// without it); --disable-coloring strips ANSI for cleaner parser
// input per V3 + V4 empirical convention.
//
// Per Task 7.1 D-PLAN-2 BuildArgs no-logger pattern: empty target URL
// returns nil argv → DockerRunner.Run() surfaces exec-empty-command
// error path. BuildArgs signature lacks logger param per framework
// contract; logging deferred to v1.1+ framework extension if needed.
//
// argv[0] = "sqlmap" per Container.Exec ContainerExecCreate.Cmd
// full-argv convention (mirrors Trivy + Nmap precedent).
//
// Task 7.5e D-PLAN-7.5e-Phase2-Entrypoint universal fix
// (Entrypoint: []string{} in container.Config) overrides parrotsec/
// sqlmap's ENTRYPOINT=[sqlmap]; the argv's "sqlmap" binary-name first
// element re-establishes the binary invocation cleanly.
func buildArgs(target tools.Target, cfg tools.ScanConfig) []string {
	if target.URL == "" {
		return nil
	}
	args := []string{
		"sqlmap",
		"-u", target.URL,
		"--batch",
		"--disable-coloring",
	}
	level, risk := depthToLevelRisk(cfg.Depth)
	args = append(args, "--level="+level, "--risk="+risk)
	return args
}

// depthToLevelRisk maps ScanConfig.Depth string to SQLMap --level
// and --risk numeric strings per Q5 (a) lock. Unknown values default
// to "quick" mapping (level=1, risk=1) for defensive forward-compat
// — future Depth enum additions surface as conservative quick scans
// rather than failing.
func depthToLevelRisk(depth string) (level, risk string) {
	switch depth {
	case "standard":
		return "3", "2"
	case "deep":
		return "5", "3"
	default:
		// "quick", "", and any unknown value default to level=1 risk=1
		return "1", "1"
	}
}
