// Command shieldscan-agent is the on-prem agent (M14; On-Prem Agent
// Design v1.0): the engine's job processor, run inside a customer's
// network, talking to the ShieldScan API over outbound HTTPS only.
//
//	shieldscan-agent enroll --api https://app.example.com --token ss_enrol_…
//	shieldscan-agent run
//	shieldscan-agent doctor [--api https://…]
//	shieldscan-agent version
//
// Like the worker (ADR-013) it has no database access; unlike the
// worker it has no Redis either — the API gateway is its only peer.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog"

	"github.com/odyssey/shieldscan-engine/internal/agent"
)

// version is set by the release build (-ldflags "-X main.version=…");
// "dev" otherwise. The heartbeat carries it so the Agents page can show
// who is behind.
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr *os.File) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	log := zerolog.New(stderr).With().Timestamp().Str("app", "shieldscan-agent").Logger()
	if lvl, err := zerolog.ParseLevel(strings.ToLower(envOr("SHIELDSCAN_LOG_LEVEL", "info"))); err == nil {
		log = log.Level(lvl)
	}
	agent.PrependToolsDir("")

	// ADR-021 Rule 3: Background() at process entry only.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch args[0] {
	case "version", "--version", "-v":
		_, _ = fmt.Fprintf(stdout, "shieldscan-agent %s (%s/%s, %s)\n", version, runtime.GOOS, runtime.GOARCH, runtime.Version())
		return 0
	case "enroll":
		return cmdEnroll(ctx, args[1:], stdout, stderr, log)
	case "run":
		return cmdRun(ctx, args[1:], stderr, log)
	case "doctor":
		return cmdDoctor(ctx, args[1:], stdout, stderr)
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		usage(stderr)
		return 2
	}
}

func usage(w *os.File) {
	_, _ = fmt.Fprint(w, `shieldscan-agent — ShieldScan on-prem scanning agent

Commands:
  enroll --api <url> --token <ss_enrol_…>   exchange a one-time token for an agent key
  run                                        heartbeat and run jobs (foreground; use the systemd unit)
  doctor [--api <url>]                       show which tools are installed and whether the API is reachable
  version                                    print the version

Environment:
  SHIELDSCAN_AGENT_STATE_DIR   where agent.json lives (default /var/lib/shieldscan-agent or ~/.shieldscan-agent)
  SHIELDSCAN_TOOLS_DIR         extra directory searched first for nuclei, nmap, httpx, …
  SHIELDSCAN_NUCLEI_TEMPLATES  nuclei templates directory (default ~/nuclei-templates)
  SHIELDSCAN_LOG_LEVEL         trace|debug|info|warn|error (default info)
`)
}

func cmdEnroll(ctx context.Context, args []string, stdout, stderr *os.File, log zerolog.Logger) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(stderr)
	api := fs.String("api", envOr("SHIELDSCAN_API", ""), "API base URL, e.g. https://app.example.com")
	token := fs.String("token", "", "one-time enrolment token from Settings → Agents")
	stateDir := fs.String("state-dir", agent.DefaultStateDir(), "where to keep agent.json")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *api == "" || *token == "" {
		_, _ = fmt.Fprintln(stderr, "enroll: --api and --token are required")
		return 2
	}
	if !strings.HasPrefix(*api, "https://") && !isLocal(*api) {
		_, _ = fmt.Fprintln(stderr, "enroll: --api must be https:// (http:// is allowed for localhost only)")
		return 2
	}
	ectx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	st, err := agent.Enroll(ectx, *api, *token, *stateDir, version, log)
	if err != nil {
		if errors.Is(err, agent.ErrEnrolmentTokenInvalid) {
			_, _ = fmt.Fprintln(stderr, "enroll: the token was not accepted — it is unknown, expired (24 h) or already used. Create a new agent in Settings → Agents.")
			return 1
		}
		_, _ = fmt.Fprintf(stderr, "enroll: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "enrolled as %q (agent %s)\nkey saved to %s/agent.json (mode 0600)\nnext: shieldscan-agent run\n",
		st.Name, st.AgentID, *stateDir)
	return 0
}

func cmdRun(ctx context.Context, args []string, stderr *os.File, log zerolog.Logger) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	stateDir := fs.String("state-dir", agent.DefaultStateDir(), "where agent.json lives")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	st, err := agent.LoadState(*stateDir)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "run: %v\n", err)
		return 1
	}
	err = agent.Run(ctx, agent.RunConfig{State: st, Version: version, Log: log})
	if errors.Is(err, agent.ErrRevoked) {
		_, _ = fmt.Fprintln(stderr, "run: this agent was revoked; remove it from the machine or enroll a new one")
		_ = agent.RemoveState(*stateDir)
		return 3
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "run: %v\n", err)
		return 1
	}
	return 0
}

func cmdDoctor(ctx context.Context, args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(stderr)
	api := fs.String("api", envOr("SHIELDSCAN_API", ""), "API base URL to probe (defaults to the enrolled one)")
	stateDir := fs.String("state-dir", agent.DefaultStateDir(), "where agent.json lives")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	_, _ = fmt.Fprintf(stdout, "shieldscan-agent %s (%s/%s)\n\n", version, runtime.GOOS, runtime.GOARCH)

	bad := 0
	inv := agent.Inventory(ctx)
	_, _ = fmt.Fprintln(stdout, "tools:")
	for _, name := range agent.ToolNames() {
		h := inv[name]
		switch h.Status {
		case "ok":
			_, _ = fmt.Fprintf(stdout, "  %-10s ok       %s  (%s)\n", name, h.Version, h.Path)
		case "missing":
			bad++
			_, _ = fmt.Fprintf(stdout, "  %-10s MISSING  install it or set SHIELDSCAN_TOOLS_DIR\n", name)
		default:
			bad++
			_, _ = fmt.Fprintf(stdout, "  %-10s ERROR    %s (%s)\n", name, h.Error, h.Path)
		}
	}

	_, _ = fmt.Fprintln(stdout)
	st, serr := agent.LoadState(*stateDir)
	switch {
	case serr == nil:
		_, _ = fmt.Fprintf(stdout, "enrolment: %s as %q (agent %s)\n", *stateDir+"/agent.json", st.Name, st.AgentID)
		if *api == "" {
			*api = st.APIBase
		}
	case errors.Is(serr, agent.ErrNotEnrolled):
		_, _ = fmt.Fprintln(stdout, "enrolment: not enrolled")
	default:
		bad++
		_, _ = fmt.Fprintf(stdout, "enrolment: %v\n", serr)
	}

	if *api != "" {
		pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		req, _ := http.NewRequestWithContext(pctx, http.MethodGet, strings.TrimRight(*api, "/")+"/v1/plans", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			bad++
			_, _ = fmt.Fprintf(stdout, "api:       %s unreachable: %v\n", *api, err)
		} else {
			_ = resp.Body.Close()
			_, _ = fmt.Fprintf(stdout, "api:       %s reachable (HTTP %d)\n", *api, resp.StatusCode)
		}
	}
	if bad > 0 {
		_, _ = fmt.Fprintf(stdout, "\n%d problem(s)\n", bad)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "\nall good")
	return 0
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func isLocal(api string) bool {
	return strings.HasPrefix(api, "http://localhost") || strings.HasPrefix(api, "http://127.0.0.1")
}
