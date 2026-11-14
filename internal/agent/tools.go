package agent

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/odyssey/shieldscan-engine/internal/tools/docker/nmap"
	"github.com/odyssey/shieldscan-engine/internal/tools/nikto"
	"github.com/odyssey/shieldscan-engine/internal/tools/nuclei"
	"github.com/odyssey/shieldscan-engine/internal/tools/sslyze"
	"github.com/odyssey/shieldscan-engine/internal/tools/wapiti"
	"github.com/odyssey/shieldscan-engine/internal/worker"
)

// The agent's tool set (design §5, Task 14.2): the seven native tools.
// nuclei, sslyze, nikto, wapiti and nmap are ToolRunners; subfinder and
// httpx are the recon helpers RunRecon execs itself. ZAP and MobSF stay
// in the cloud. Unlike the worker, a missing tool is not fatal: it is
// reported as "missing" in every heartbeat and `doctor`, and a job for
// it fails with the usual "no runner registered" completion, so the
// operator sees exactly what to install.

// toolSpec is one tool the agent knows how to find and to ask for a version.
type toolSpec struct {
	Name        string
	Binary      string   // name on PATH
	EnvVar      string   // SHIELDSCAN_<TOOL>_BINARY override (same names as the worker)
	VersionArgs []string // argv to print the version
	Runner      bool     // registered as a ToolRunner (false: recon helper)
}

var toolSpecs = []toolSpec{
	{"nuclei", "nuclei", "SHIELDSCAN_NUCLEI_BINARY", []string{"-version"}, true},
	{"sslyze", "sslyze", "SHIELDSCAN_SSLYZE_BINARY", []string{"--version"}, true},
	{"nikto", "nikto", "SHIELDSCAN_NIKTO_BINARY", []string{"-Version"}, true},
	{"wapiti", "wapiti", "SHIELDSCAN_WAPITI_BINARY", []string{"--version"}, true},
	{"nmap", "nmap", "SHIELDSCAN_NMAP_BINARY", []string{"--version"}, true},
	{"subfinder", "subfinder", "SHIELDSCAN_SUBFINDER_BINARY", []string{"-version"}, false},
	{"httpx", "httpx", "SHIELDSCAN_HTTPX_BINARY", []string{"-version"}, false},
}

// ToolNames lists the agent's tools in display order.
func ToolNames() []string {
	out := make([]string, 0, len(toolSpecs))
	for _, s := range toolSpecs {
		out = append(out, s.Name)
	}
	return out
}

// PrependToolsDir puts SHIELDSCAN_TOOLS_DIR (or the given dir) at the
// front of PATH so every exec.LookPath in this process — the runners'
// and recon's — finds the operator's copies first.
func PrependToolsDir(dir string) {
	if dir == "" {
		dir = os.Getenv("SHIELDSCAN_TOOLS_DIR")
	}
	if dir == "" {
		return
	}
	_ = os.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// Inventory probes every tool: where it is and what version it reports.
// Each probe is bounded (5 s) so a hung binary cannot stall a heartbeat.
func Inventory(ctx context.Context) map[string]ToolHealth {
	out := make(map[string]ToolHealth, len(toolSpecs))
	for _, s := range toolSpecs {
		out[s.Name] = probe(ctx, s)
	}
	return out
}

func resolve(s toolSpec) (string, bool) {
	if p := os.Getenv(s.EnvVar); p != "" {
		if _, err := os.Stat(p); err == nil { //nolint:gosec // G703: operator-supplied binary path from the environment, by design
			return p, true
		}
		return p, false
	}
	p, err := exec.LookPath(s.Binary)
	return p, err == nil
}

func probe(ctx context.Context, s toolSpec) ToolHealth {
	path, ok := resolve(s)
	if !ok {
		return ToolHealth{Status: "missing"}
	}
	pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(pctx, path, s.VersionArgs...) //nolint:gosec // G204: resolved binary, fixed argv
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	version := firstVersionLine(buf.String())
	if err != nil && version == "" {
		return ToolHealth{Status: "error", Path: path, Error: strings.TrimSpace(firstLine(err.Error()))}
	}
	return ToolHealth{Status: "ok", Path: path, Version: version}
}

// firstVersionLine picks the first line that carries a digit — the
// tools print banners, warnings and update nags around the number.
func firstVersionLine(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(stripANSI(line))
		if line == "" || !strings.ContainsAny(line, "0123456789") {
			continue
		}
		if len(line) > 80 {
			line = line[:80]
		}
		return line
	}
	return ""
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func stripANSI(s string) string {
	var b strings.Builder
	esc := false
	for _, r := range s {
		switch {
		case esc:
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				esc = false
			}
		case r == 0x1b:
			esc = true
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// BuildRegistry constructs the ToolRunner registry from whatever is
// installed. Returns the registry and the names it could not register.
// Agent-side nmap allows RFC1918 and loopback targets: the agent is
// inside the network it scans, which is the whole point (design A5).
func BuildRegistry(log zerolog.Logger) (*worker.Registry, []string) {
	runners := map[string]tools.ToolRunner{}
	var missing []string
	for _, s := range toolSpecs {
		if !s.Runner {
			continue
		}
		path, ok := resolve(s)
		if !ok {
			missing = append(missing, s.Name)
			continue
		}
		switch s.Name {
		case "nuclei":
			runners[s.Name] = nuclei.NewNucleiRunner(nuclei.Config{
				BinaryPath:   path,
				TemplatesDir: nucleiTemplatesDir(),
				DefaultRPS:   50,
			}, log)
		case "sslyze":
			runners[s.Name] = sslyze.NewSSLyzeRunner(sslyze.Config{BinaryPath: path}, log)
		case "nikto":
			runners[s.Name] = nikto.NewNiktoRunner(nikto.Config{
				BinaryPath: path,
				TLSCapable: envEnabled("SHIELDSCAN_NIKTO_TLS_CAPABLE"),
			}, log)
		case "wapiti":
			runners[s.Name] = wapiti.NewWapitiRunner(wapiti.Config{BinaryPath: path}, log)
		case "nmap":
			runners[s.Name] = nmap.NewNativeRunner(nmap.NativeConfig{
				BinaryPath: path, AllowPrivateTargets: true, AllowLoopback: true,
			}, log)
		}
	}
	return worker.NewRegistry(runners), missing
}

func nucleiTemplatesDir() string {
	if d := os.Getenv("SHIELDSCAN_NUCLEI_TEMPLATES"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "nuclei-templates"
	}
	return filepath.Join(home, "nuclei-templates")
}

func envEnabled(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
