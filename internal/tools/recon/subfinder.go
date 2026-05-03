package recon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"github.com/odyssey/shieldscan-engine/internal/tools/jsonx"
)

// subfinderTimeout is the per-tool default timeout. Mirrors plan §6.3
// literal (`60 * time.Second`); customer demand may extend later.
const subfinderTimeout = 60 * time.Second

// runSubfinder invokes Subfinder against domain and returns
// discovered subdomains as a deduplicated slice.
//
// Per ADR-022 + H.NEW.5: direct exec.CommandContext (NOT via
// NativeRunner). Subfinder produces subdomain strings, not findings;
// NativeRunner's enrichment loop is irrelevant.
//
// Per H.NEW.3: passive sources only (no -all flag) — conservative
// default to avoid triggering DoS detection on intel sources.
//
// Per H.NEW.8 / TOOL-ARCH §6.3 patch: -oJ JSONL output (not -o -
// text), parsed via parseSubfinderOutput.
func runSubfinder(ctx context.Context, domain string, timeout time.Duration) ([]string, error) {
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	binary, err := resolveBinary("SHIELDSCAN_SUBFINDER_BINARY", "subfinder")
	if err != nil {
		return nil, err
	}

	// Conservative invocation: passive sources only; JSONL output to
	// stdout; -silent suppresses banner; -max-time enforces tool-side
	// timeout in addition to outer ctx.
	cmd := exec.CommandContext(runCtx, binary, //nolint:gosec // G204: env-resolved binary path; in-repo arg construction
		"-d", domain,
		"-oJ",
		"-silent",
		"-max-time", "60",
	)
	out, err := cmd.Output()
	if err != nil {
		// Caller cancellation takes precedence over tool error.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("subfinder: exec: %w", err)
	}
	return parseSubfinderOutput(out), nil
}

// parseSubfinderOutput parses Subfinder's `-oJ` JSONL output into
// a deduplicated slice of subdomain strings.
//
// Subfinder JSONL shape:
//
//	{"host":"api.example.com","input":"example.com","source":"crtsh"}
//
// Parser extracts only `host`. `input` and `source` are operational
// diagnostics (which root domain triggered this hit; which intel
// source produced it); dropped from the canonical output.
//
// Malformed lines are dropped silently (parser doesn't take a logger;
// per 6.1 Nuclei JSONL precedent the dispatcher handles the wider
// failure-tolerance).
func parseSubfinderOutput(stdout []byte) []string {
	if len(stdout) == 0 {
		return nil
	}
	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	// Subfinder lines are short (~100 bytes typical); 64 KiB default
	// scanner buffer is sufficient.
	seen := map[string]struct{}{}
	out := []string{}
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			continue // malformed JSONL line; drop silently
		}
		host := jsonx.ExtractString(rec, "host")
		if host == "" {
			continue // record missing required field
		}
		if _, ok := seen[host]; ok {
			continue // dedup
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	return out
}
