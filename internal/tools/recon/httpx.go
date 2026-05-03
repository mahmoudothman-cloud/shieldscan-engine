package recon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/odyssey/shieldscan-engine/internal/tools/jsonx"
)

// httpxTimeout is the per-tool default. Mirrors plan §6.3 literal
// (`120 * time.Second`); httpx probing N hosts can take longer than
// subfinder's discovery phase.
const httpxTimeout = 120 * time.Second

// runHttpx invokes httpx against the given subdomain list and
// returns LiveHost metadata for hosts that responded successfully.
//
// Per ADR-022 + H.NEW.5: direct exec.CommandContext (NOT via
// NativeRunner). httpx produces LiveHost metadata, not findings.
//
// Per H.NEW.6 + empirical re-eval at M6.3 implementation: subdomain
// list passed via STDIN PIPE (not inline tempfile). Empirical
// verification confirmed httpx stdin pipe doesn't suffer Wapiti-
// style stdout corruption — 3 hosts piped via stdin produced 3
// clean JSONL records on stdout. Inline-tempfile workaround pattern
// stays at 1 instance (CORStest only); InputFile framework
// extension trigger pin remains at 1st-instance need.
//
// Per H.NEW.4: feature-flag set extracts the 6 LiveHost fields.
func runHttpx(ctx context.Context, subdomains []string, timeout time.Duration) ([]LiveHost, error) {
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	binary, err := resolveBinary("SHIELDSCAN_HTTPX_BINARY", "httpx")
	if err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(runCtx, binary, //nolint:gosec // G204: env-resolved binary path; in-repo arg construction
		"-silent",
		"-json",
		"-status-code",
		"-title",
		"-tech-detect",
		"-web-server",
	)

	// Stdin-pipe pattern (per empirical re-eval): pipe subdomain
	// list via stdin rather than inline tempfile + -l flag. Cleaner;
	// no tempfile lifecycle; verified clean output at pre-prep.
	cmd.Stdin = strings.NewReader(strings.Join(subdomains, "\n") + "\n")

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("httpx: stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("httpx: start: %w", err)
	}
	out, readErr := io.ReadAll(stdoutPipe)
	waitErr := cmd.Wait()
	if waitErr != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("httpx: exec: %w", waitErr)
	}
	if readErr != nil {
		return nil, fmt.Errorf("httpx: read stdout: %w", readErr)
	}
	return parseHttpxOutput(out), nil
}

// parseHttpxOutput parses httpx `-json` JSONL output into LiveHost
// records. `failed: true` records are EXCLUDED from output (filtered
// during parse — they signal unreachable hosts, not data we want
// passed to M8 as scan targets).
//
// Field map (httpx JSONL → LiveHost; per H.NEW.1 6-field shape):
//
//	url           → URL
//	status_code   → StatusCode
//	title         → Title
//	tech          → Tech
//	webserver     → Webserver
//	content_type  → ContentType
//
// Other fields (host, port, path, method, time, a/aaaa, cdn*,
// knowledgebase, resolvers, words/lines, content_length, timestamp)
// are dropped — M8 unlikely to need.
//
// Malformed lines dropped silently (parser doesn't take a logger;
// per 6.1 Nuclei JSONL precedent).
func parseHttpxOutput(stdout []byte) []LiveHost {
	if len(stdout) == 0 {
		return nil
	}
	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	// httpx lines can be larger than 64 KiB when title or response
	// metadata is long; bump scanner buffer cap.
	scanner.Buffer(make([]byte, 0, 64*1024), 1*1024*1024)

	out := []LiveHost{}
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		// Filter failed:true records (unreachable hosts).
		if failed, _ := rec["failed"].(bool); failed {
			continue
		}
		url := jsonx.ExtractString(rec, "url")
		if url == "" {
			continue // require URL as identifier
		}
		out = append(out, LiveHost{
			URL:         url,
			StatusCode:  int(jsonx.ExtractFloat(rec, "status_code")),
			Title:       jsonx.ExtractString(rec, "title"),
			Tech:        jsonx.ExtractStringSlice(rec, "tech"),
			Webserver:   jsonx.ExtractString(rec, "webserver"),
			ContentType: jsonx.ExtractString(rec, "content_type"),
		})
	}
	return out
}
