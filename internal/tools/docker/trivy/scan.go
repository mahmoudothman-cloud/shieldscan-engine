package trivy

import (
	"github.com/odyssey/shieldscan-engine/internal/tools"
)

// buildArgsImage produces the argv for Trivy image-mode scans:
//
//	trivy image --format json --scanners vuln --exit-code 0 <image-ref>
//
// Per PRE-P1 Y1 lock (ExitCodeLenient: true + explicit --exit-code 0
// flag bundle; defense-in-depth: framework leniency catches any
// behavior drift if a future Trivy version changes default exit-code
// semantics) + Y2 lock (Target.URL carries the image reference string
// for container mode; container mode is target.TargetType=="container"
// in caller convention but BuildArgs does not enforce — the orchestrator
// is responsible for routing TrivyContainerScanner to container-mode
// targets per Q2 dual-registration lock).
//
// Per Nmap forward-pin Option α disposition (plan §3.4): BuildArgs
// signature returns []string only (no error); empty target produces
// nil argv → DockerRunner.Run detects nil/empty command and surfaces
// an exec error. ADR-026 line 2093 escape hatch covers if empirical
// pressure surfaces the buildArgs-error-return framework gap.
//
// argv[0] is the binary name "trivy" per Container.Exec convention
// (ContainerExecCreate.Cmd takes the full argv including binary).
func buildArgsImage(target tools.Target, cfg tools.ScanConfig) []string {
	_ = cfg // cfg.Depth / cfg.Timeout reserved for v1.1+ tunables
	if target.URL == "" {
		return nil
	}
	return []string{
		"trivy",
		"image",
		"--format", "json",
		"--scanners", "vuln",
		"--exit-code", "0",
		target.URL,
	}
}

// buildArgsFs produces the argv for Trivy fs-mode (filesystem) scans:
//
//	trivy fs --format json --scanners vuln --exit-code 0 <path>
//
// Per PRE-P1 Y1 + Y2 locks. Y2 routes Target.SourcePath as the fs
// scan target (fs-mode scans dependency manifests within a directory
// tree per Phase 0 v2 fixture: Gemfile.lock + package-lock.json +
// requirements.txt etc.).
//
// Same empty-target → nil argv discipline as buildArgsImage. Same
// argv[0]="trivy" convention.
func buildArgsFs(target tools.Target, cfg tools.ScanConfig) []string {
	_ = cfg
	if target.SourcePath == "" {
		return nil
	}
	return []string{
		"trivy",
		"fs",
		"--format", "json",
		"--scanners", "vuln",
		"--exit-code", "0",
		target.SourcePath,
	}
}
