package nikto

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/odyssey/shieldscan-engine/internal/events"
	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/rs/zerolog"
)

// Soft-404 verification: dropping file-existence findings that a
// catch-all route manufactured.
//
// THE PROBLEM. Nikto's file-existence checks conclude a path exists from
// the response to a request for it — for most of them, simply a 200. A
// single-page application serves its shell for every unmatched path, so
// against a React / Angular / Vue app with a catch-all every path in the
// database "exists". Observed on a live scan: /.htpasswd reported as
// "Contains authorization information" when the 75002 bytes returned
// were the app's index.html, byte-identical to what /.env, /.git/config
// and a random path all returned.
//
// WHAT NIKTO ALREADY DOES, because this pass is deliberately narrow.
// Nikto has a soft-404 filter and it is good: at scan start it probes a
// random path per bucket, and for a 200 stores an md4 of the body with
// dates, numbers and the requested URI stripped out (%FoF and is_404 in
// nikto_core.plugin). Two things limit it, both structural:
//
//   - The filter is CONDITIONAL. nikto_tests.plugin:252 consults is_404
//     only when the test matched on a response CODE:
//
//     if (($m1_method eq "code") || ($m1o_method eq "code")) {
//     if (is_404(...)) { next; }
//     }
//
//     A test that matches on response CONTENT bypasses it entirely.
//     That is why /.env (match "200") was correctly suppressed on the
//     live scan while /.htpasswd (match ".:.+", a regex that matches
//     almost any HTML) was not.
//
//   - Stripping the requested URI from the body before hashing means a
//     path whose own name appears in the page hashes differently from
//     the baseline. /public/ was reported for exactly that reason: the
//     literal string "/public/" occurs once in the shell and in no
//     other tested path, so its cooked hash diverged. Verified with
//     Nikto's own LW2::md4 — /admin/, /backup/ and /test/ all hashed to
//     the baseline and were suppressed; /public/ did not.
//
// Measured against a total catch-all, a simulation of all 6946 tests
// validated against the live scan fires 2 (0.03%) — so Nikto's filter
// carries almost all of the load. This pass exists for the residue, and
// because the size of that residue is a property of the TARGET'S HTML
// rather than of the corpus: /public/ escaped only because that string
// happened to be in this shell. A Next.js or Nuxt shell referencing
// /static/, /assets/, /api/ and /admin/ would leak one per occurrence,
// and we neither control nor can predict which.
//
// WHY IT IS HERE AND NOT IN THE PARSER. Nikto's XML carries id, method,
// description and uri — no response bodies — so there is nothing in the
// report to compare. Deciding this needs a request, which means ctx and
// the target, which the parser has neither of. Hence the PostProcess
// hook on NativeRunner.
//
// THE DELIBERATE DIVERGENCE FROM NIKTO: raw bodies, compared byte for
// byte, with the requested URI NOT stripped. That is the one thing done
// differently, and it is what catches /public/. Stripping the URI is
// what let /public/ through, and it buys Nikto robustness against pages
// that echo the request — at the cost of treating a page that merely
// MENTIONS the path as a different page. Since both sides of our
// comparison come from the same host moments apart, we do not need that
// robustness: if the bytes differ at all, we keep the finding.
//
// WHY A BYTE-IDENTICAL MATCH IS A SOUND REASON TO DROP. The two
// responses being identical means the server returned the same bytes for
// the reported path and for a path chosen at random, which is what
// "there is no file here" looks like from outside. The alternative
// reading — that a real file at the reported path is also served at the
// random control path — is itself the catch-all case.

// verifyBudget bounds the WHOLE pass, as a child of the run context.
//
// Without it the pass inherits whatever is left of the 15-minute tool
// timeout, and a target that blackholes connections would spend all of
// it timing out one probe at a time. Two minutes covers the observed
// shape by a wide margin (a live scan produced 3 candidates, so 3 target
// probes plus 2 distinct controls, in under a second) while capping the
// worst case at something that does not distort scan duration. Exceeding
// it is not an error: every candidate not yet decided is kept.
const verifyBudget = 2 * time.Minute

// verifyProbeTimeout bounds a single request. Short on purpose — this is
// one GET to a host Nikto has just made thousands of requests to, so a
// slow response is far more likely to be a rate limiter or a WAF than a
// page worth waiting for, and the fail-open answer costs nothing.
const verifyProbeTimeout = 15 * time.Second

// verifyMaxBodyBytes caps a body read. A response larger than this is
// treated as undecidable rather than compared, so the pass cannot be
// made to buffer an arbitrary amount of a target's choosing. 4 MiB is
// ~55x the app shell that motivated this.
const verifyMaxBodyBytes = 4 << 20

// verifyUserAgent identifies the probe in the target's access log.
//
// It deliberately does NOT impersonate Nikto's UA. The invariant this
// pass needs is that its TWO requests are made identically as each
// other, not that either resembles the scanner's — a server that treats
// our UA differently from Nikto's gives us two responses that differ
// from Nikto's but agree with each other, which still answers the
// question. Being identifiable is worth more than the fidelity.
const verifyUserAgent = "ShieldScan/1.0 (nikto soft-404 verification)"

// controlExt constrains which extensions a control path is built from.
//
// A control has to sit in the same routing bucket as the reported path,
// which for an extension bucket means carrying the same extension. Nikto
// probe paths include shapes whose "extension" is punctuation —
// /index.html~, /sam._, /admin/settings.inc.php+, /*.* — and appending
// those to a random basename produces a request whose shape is not
// reliably the sibling of anything. Those are skipped, which keeps the
// finding: 47 of the 3008 existence-check tests, plus 25 whose uri is
// the bare root and therefore has no sibling, so 2.4% of candidates are
// undecidable by construction and stay.
var controlExt = regexp.MustCompile(`^[A-Za-z0-9]{1,16}$`)

// verifySoftNotFound returns a NativeRunner.PostProcess closure.
func verifySoftNotFound(log zerolog.Logger) func(context.Context, tools.Target, tools.ScanConfig, []events.RawFinding) []events.RawFinding {
	return func(ctx context.Context, _ tools.Target, _ tools.ScanConfig, findings []events.RawFinding) []events.RawFinding {
		return newVerifier(log).run(ctx, findings)
	}
}

// probeResult is one fetched response, or the reason there isn't one.
//
// A DIGEST is kept rather than the body. Bodies are compared exactly
// once and never read again, so retaining them only bounds the pass's
// memory by (candidates x body size) — and the candidate ceiling is the
// 3008 existence-check tests, not the handful a healthy target produces.
// Hashing makes the memoisation cost 40 bytes per URL whatever the
// target serves, which is what lets the cache be held for the whole
// pass without a second cap on top of the body cap.
type probeResult struct {
	status int
	digest [sha256.Size]byte
	length int
	// usable is false when the response could not be reduced to a
	// comparable digest — today only an over-cap body. Distinct from
	// err (no response at all) and from a genuinely empty body, which
	// is usable and has the digest of zero bytes.
	usable bool
	err    error
}

// verifier holds the per-run probe state. One is built per scan so the
// control nonce — and therefore the control URLs, and therefore the
// cache — is scoped to a single pass.
type verifier struct {
	log    zerolog.Logger
	client *http.Client
	nonce  string
	cache  map[string]probeResult
}

func newVerifier(log zerolog.Logger) *verifier {
	return &verifier{
		log:    log,
		client: newVerifyClient(),
		nonce:  controlNonce(),
		cache:  map[string]probeResult{},
	}
}

// newVerifyClient builds the probe client.
//
// Redirects are NOT followed (ErrUseLastResponse). The question is what
// each path returns, and following a redirect answers a different one —
// a reported path that 301s somewhere real and a control path that 404s
// would otherwise be compared at their destinations rather than at
// themselves. Not following also makes the status comparison meaningful.
//
// Timeout is 0 because ctx carries the bound, matching the convention in
// internal/tools/docker/service/readiness.go.
func newVerifyClient() *http.Client {
	return &http.Client{
		Timeout:       0,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			// Certificates are deliberately not validated, and the reason
			// is fidelity rather than convenience: Nikto (via LW2) does
			// not validate either, so a target with a self-signed or
			// expired certificate is one Nikto scanned and produced
			// findings for. Refusing to probe it would make this pass
			// silently inert on exactly the population most likely to be
			// misconfigured, and "inert" here means the false positives
			// stay.
			//
			// Nothing is trusted on the strength of the connection: the
			// two bodies are compared against EACH OTHER, never parsed,
			// and a mismatch keeps the finding. Certificate validity is a
			// finding SSLyze reports on its own; it is not this pass's
			// question.
			//
			// MinVersion is pinned low for the same reason — Go's client
			// default refuses TLS 1.0/1.1, and a server that old is one
			// Nikto reached and we otherwise could not.
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // G402: see comment above
				MinVersion:         tls.VersionTLS10,
			},
		},
	}
}

// controlNonce returns the random component of every control path.
//
// crypto/rand rather than math/rand, because unpredictability is load
// bearing and not incidental: a predictable control path is one a target
// could serve real content at, turning every drop into a kept false
// positive. On failure the pass is abandoned (empty nonce), which keeps
// every finding — a guessable control would be worse than no pass.
func controlNonce() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return hex.EncodeToString(b)
}

// run is the pass. It never returns an error: see NativeRunner.PostProcess.
func (v *verifier) run(ctx context.Context, findings []events.RawFinding) []events.RawFinding {
	candidates := 0
	for i := range findings {
		if isExistenceCheck(findings[i].FindingType) {
			candidates++
		}
	}
	// Nothing to verify means no requests at all. The common case for
	// most targets, and worth keeping free.
	if candidates == 0 || v.nonce == "" {
		return findings
	}

	passCtx, cancel := context.WithTimeout(ctx, verifyBudget)
	defer cancel()
	defer v.client.CloseIdleConnections()

	started := time.Now()
	kept := make([]events.RawFinding, 0, len(findings))
	dropped, undecided := 0, 0

	for _, f := range findings {
		if !isExistenceCheck(f.FindingType) {
			kept = append(kept, f)
			continue
		}
		drop, reason, detail := v.decide(passCtx, f)
		if drop {
			dropped++
			// INFO, not DEBUG, and with everything needed to check the
			// call by hand. This pass second-guesses the scanner, so a
			// wrong drop is a false negative in a security product —
			// the failure mode that hides rather than annoys. Every one
			// of them has to be findable in a log without a rebuild.
			v.log.Info().
				Str("finding_type", f.FindingType).
				Str("target_url", f.TargetURL).
				Str("control_url", detail.controlURL).
				Int("http_status", detail.status).
				Int("body_bytes", detail.bodyLen).
				Str("reason", reason).
				Msg("nikto: dropping file-existence finding; the target answers a random control path identically, so the path is a catch-all route and not a file")
			continue
		}
		if !decidedKeep(reason) {
			undecided++
		}
		v.log.Debug().
			Str("finding_type", f.FindingType).
			Str("target_url", f.TargetURL).
			Str("control_url", detail.controlURL).
			Str("reason", reason).
			Msg("nikto: keeping file-existence finding")
		kept = append(kept, f)
	}

	v.log.Info().
		Int("candidates", candidates).
		Int("dropped", dropped).
		Int("kept_undecided", undecided).
		Int("requests", len(v.cache)).
		Dur("took", time.Since(started)).
		Msg("nikto: soft-404 verification complete")

	return kept
}

// Reasons recorded on every decision. They are the log's whole value, so
// they name the mechanism rather than the outcome.
const (
	reasonIdentical      = "target and control returned identical status and body"
	reasonBodiesDiffer   = "bodies differ"
	reasonStatusDiffers  = "status differs"
	reasonNoControl      = "no sibling control path can be built for this uri"
	reasonTargetProbe    = "re-fetching the reported path failed"
	reasonControlProbe   = "fetching the control path failed"
	reasonOversize       = "a response exceeded the comparable-body cap"
	reasonBudgetExceeded = "verification budget exhausted before this finding"
)

// decidedKeep separates a keep the pass CONCLUDED from a keep it merely
// defaulted to. Both keep the finding, so the distinction changes no
// behaviour — it exists so kept_undecided in the summary log means "the
// pass could not answer", which is the number worth watching. A target
// whose kept_undecided equals its candidate count is one where this pass
// is doing nothing, and that should be visible rather than look like a
// clean verification.
func decidedKeep(reason string) bool {
	return reason == reasonBodiesDiffer || reason == reasonStatusDiffers
}

// decisionDetail is the evidence behind one decision, for the log.
type decisionDetail struct {
	controlURL string
	status     int
	bodyLen    int
}

// decide resolves one candidate finding.
//
// EVERY path out of it except one keeps the finding. That asymmetry is
// the design: dropping requires positive evidence that the target
// answers an arbitrary path the same way, and anything less — a failed
// probe, an expired budget, a uri with no sibling, a body too large to
// compare — is a reason to leave the scanner's conclusion alone.
func (v *verifier) decide(ctx context.Context, f events.RawFinding) (bool, string, decisionDetail) {
	if err := ctx.Err(); err != nil {
		return false, reasonBudgetExceeded, decisionDetail{}
	}

	controlURL, ok := controlURLFor(f.TargetURL, v.nonce)
	if !ok {
		return false, reasonNoControl, decisionDetail{}
	}
	d := decisionDetail{controlURL: controlURL}

	target := v.fetch(ctx, f.TargetURL)
	if target.err != nil {
		return false, reasonTargetProbe, d
	}
	control := v.fetch(ctx, controlURL)
	if control.err != nil {
		return false, reasonControlProbe, d
	}
	d.status = target.status
	d.bodyLen = target.length

	if !target.usable || !control.usable {
		return false, reasonOversize, d
	}
	if target.status != control.status {
		return false, reasonStatusDiffers, d
	}
	if target.digest != control.digest {
		return false, reasonBodiesDiffer, d
	}
	return true, reasonIdentical, d
}

// fetch performs one GET, memoised per URL.
//
// The cache is what keeps this N+1 rather than 2N: findings share
// buckets, so /ftp/ and /public/ resolve to the same control URL and
// probe it once. It also covers the case of two tests reporting
// different categories at the same uri.
//
// A body over the cap comes back usable=false with a nil error, which
// decide reads as undecidable — distinct from a failed request, and
// distinct from a genuinely empty body.
func (v *verifier) fetch(ctx context.Context, rawURL string) probeResult {
	if p, ok := v.cache[rawURL]; ok {
		return p
	}
	p := v.get(ctx, rawURL)
	if p.err != nil {
		v.log.Debug().Str("url", rawURL).Err(p.err).Msg("nikto: verification probe failed; findings at this path are kept")
	}
	v.cache[rawURL] = p
	return p
}

func (v *verifier) get(ctx context.Context, rawURL string) probeResult {
	reqCtx, cancel := context.WithTimeout(ctx, verifyProbeTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, rawURL, nil)
	if err != nil {
		return probeResult{err: fmt.Errorf("build request: %w", err)}
	}
	req.Header.Set("User-Agent", verifyUserAgent)
	// Accept-Encoding is deliberately NOT set, which leaves Go to send
	// its own "gzip" and transparently decompress. Both probes are then
	// compared as plaintext whatever the server chose to do, including
	// when it compresses one path and not another.
	//
	// An earlier version asked for "identity" on the theory that an
	// unencoded body is the more directly comparable one. Live
	// verification proved that backwards: the target declared
	// content-length 11323 on /ftp/ and sent 11264 bytes, so the read
	// failed with unexpected EOF and the genuine finding survived only
	// because the probe errored. Curl tolerates that mismatch silently;
	// Go does not, and Go is right. Requesting identity is the rarer
	// shape and therefore the one a server is least likely to have been
	// tested against — the default request every other client makes is
	// the one least likely to find a new server bug.

	resp, err := v.client.Do(req)
	if err != nil {
		return probeResult{err: err}
	}
	defer func() { _ = resp.Body.Close() }()

	// Hash as we read so the body is never held whole.
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(resp.Body, verifyMaxBodyBytes+1))
	if err != nil {
		// Includes a body that ends before its declared Content-Length,
		// which a live target did on its one genuine finding — see the
		// Accept-Encoding note above.
		return probeResult{err: fmt.Errorf("read body: %w", err)}
	}
	if n > verifyMaxBodyBytes {
		return probeResult{status: resp.StatusCode, length: int(n), usable: false}
	}
	p := probeResult{status: resp.StatusCode, length: int(n), usable: true}
	copy(p.digest[:], h.Sum(nil))
	return p
}

// controlURLFor builds the sibling control URL for a reported path:
// same scheme, host and parent directory, same bucket, random basename.
//
// The bucket is Nikto's own, mirrored from get_ext in
// nikto_core.plugin:179 rather than invented, so the control lands in
// whatever routing class the reported path is in:
//
//	trailing "/"            → DIRECTORY   → <parent>/<nonce>/
//	basename ^\.[^.%]       → DOTFILE     → <parent>/.<nonce>
//	basename has no "."     → NONE        → <parent>/<nonce>
//	otherwise               → extension   → <parent>/<nonce>.<ext>
//
// Note the ORDER, which is Nikto's: the dotfile test runs before the
// query string is stripped, so "/.env?x=1" is a DOTFILE.
//
// The control sits in the reported path's PARENT rather than at the site
// root, which is a small divergence from Nikto (whose baseline probes
// are all at the root) and the more accurate question: the thing being
// characterised is the route serving /admin/backup/, and /admin/<nonce>/
// characterises it while /<nonce>/ characterises the root. When the
// parent is itself protected the control comes back 401 or 403, the
// status comparison fails, and the finding is kept.
//
// Returns false when no sibling exists — the bare root, or an extension
// too odd to reproduce (see controlExt).
func controlURLFor(rawURL, nonce string) (string, bool) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "", false
	}
	path := u.Path
	if path == "" || path == "/" {
		return "", false
	}
	// Parent directory, keeping its trailing slash. For "/public/" this
	// is "/" (the trailing slash is dropped before the search so the
	// directory's own name is what gets replaced, not the empty string
	// after it).
	slash := strings.LastIndex(strings.TrimSuffix(path, "/"), "/")
	if slash < 0 {
		return "", false
	}
	parent := path[:slash+1]

	name, ok := controlName(path, nonce)
	if !ok {
		return "", false
	}

	// Rebuild from the parsed URL so scheme, host and port are carried
	// verbatim, and drop any query: the control is a path-level sibling,
	// and a query copied from a Nikto probe path would make it a
	// different request rather than a neighbouring one.
	ctl := *u
	ctl.RawQuery = ""
	ctl.Fragment = ""
	ctl.Path = parent + name
	ctl.RawPath = ""
	return ctl.String(), true
}

// controlName renders the random basename for path's bucket.
func controlName(path, nonce string) (string, bool) {
	if strings.HasSuffix(path, "/") {
		return nonce + "/", true // DIRECTORY
	}
	base := path[strings.LastIndex(path, "/")+1:]
	if len(base) > 1 && base[0] == '.' && base[1] != '.' && base[1] != '%' {
		return "." + nonce, true // DOTFILE
	}
	base = strings.SplitN(base, "?", 2)[0]
	base = strings.SplitN(base, "&", 2)[0]
	base = strings.SplitN(base, "%", 2)[0]
	dot := strings.LastIndex(base, ".")
	if dot < 0 {
		return nonce, true // NONE
	}
	ext := base[dot+1:]
	if !controlExt.MatchString(ext) {
		return "", false
	}
	return nonce + "." + ext, true
}
