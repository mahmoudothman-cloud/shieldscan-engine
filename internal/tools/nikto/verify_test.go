package nikto

import (
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/odyssey/shieldscan-engine/internal/events"
	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The live shape these tests encode, measured against the target that
// produced the false positives (Caddy in front of OWASP Juice Shop):
//
//	/public/     200  75002 bytes  sha256 48d6062945…   ← catch-all shell
//	/.htpasswd   200  75002 bytes  sha256 48d6062945…   ← catch-all shell
//	/.env        200  75002 bytes  sha256 48d6062945…
//	/<nonce>/    200  75002 bytes  sha256 48d6062945…   ← control
//	/.<nonce>    200  75002 bytes  sha256 48d6062945…   ← control
//	/ftp/        200  11264 bytes  sha256 3f6b30a23b…   ← REAL listing
//
// The shell is byte-identical across buckets and across repeats, which
// is what makes a raw comparison sufficient and a tolerance unnecessary.

const (
	shellBody   = "<!doctype html><html><body>app shell mentioning /public/ once</body></html>"
	genuineBody = "<html><head><title>listing directory /ftp/</title></head><body>files</body></html>"
)

// catchAllServer answers every path with shellBody, except the paths in
// real, and records how many times each path was requested.
type catchAllServer struct {
	*httptest.Server
	mu   sync.Mutex
	hits map[string]int
	real map[string]string
}

func newCatchAllServer(t *testing.T, real map[string]string) *catchAllServer {
	t.Helper()
	c := &catchAllServer{hits: map[string]int{}, real: real}
	c.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		c.hits[r.URL.Path]++
		c.mu.Unlock()
		if body, ok := c.real[r.URL.Path]; ok {
			_, _ = w.Write([]byte(body))
			return
		}
		_, _ = w.Write([]byte(shellBody))
	}))
	t.Cleanup(c.Close)
	return c
}

func (c *catchAllServer) hitCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, v := range c.hits {
		n += v
	}
	return n
}

func (c *catchAllServer) pathsHit() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, 0, len(c.hits))
	for p := range c.hits {
		out = append(out, p)
	}
	return out
}

// existenceFinding builds a candidate finding — one whose FindingType
// came from a Nikto category that concludes a path exists.
func existenceFinding(base, path string) events.RawFinding {
	return events.RawFinding{
		FindingType: "nikto-interesting-file",
		TargetURL:   base + path,
		Title:       path + ": This might be interesting.",
	}
}

func typeOf(findings []events.RawFinding) []string {
	out := make([]string, len(findings))
	for i, f := range findings {
		out[i] = f.TargetURL
	}
	return out
}

func runVerify(ctx context.Context, findings []events.RawFinding) []events.RawFinding {
	return verifySoftNotFound(noopLog())(ctx, tools.Target{}, tools.ScanConfig{}, findings)
}

// TestVerify_CatchAllFindingsAreDroppedAndGenuineOnesSurvive is the
// behaviour the whole pass exists for, reproducing the three findings
// the live scan produced.
//
// /ftp/ SURVIVING is the assertion that matters most: dropping it would
// mean the pass is too aggressive, and a false negative in a security
// product is the failure mode that hides rather than annoys.
func TestVerify_CatchAllFindingsAreDroppedAndGenuineOnesSurvive(t *testing.T) {
	srv := newCatchAllServer(t, map[string]string{"/ftp/": genuineBody})

	out := runVerify(t.Context(), []events.RawFinding{
		existenceFinding(srv.URL, "/ftp/"),    // genuine: real directory listing
		existenceFinding(srv.URL, "/public/"), // catch-all: the shell
		{FindingType: "nikto-info-disclosure", TargetURL: srv.URL + "/.htpasswd"},
	})

	require.Len(t, out, 1,
		"only the genuine finding should survive; got %v", typeOf(out))
	assert.Equal(t, srv.URL+"/ftp/", out[0].TargetURL,
		"/ftp/ returns a real directory listing that differs from the control, so it must be kept")
}

// TestVerify_NonExistenceFindingsAreNeverProbed pins the narrowing that
// keeps this pass cheap and safe. A content-matched finding carries its
// own evidence, so it is not second-guessed and costs no requests.
func TestVerify_NonExistenceFindingsAreNeverProbed(t *testing.T) {
	srv := newCatchAllServer(t, nil)

	// Every one of these is a curated plugin class or a non-existence
	// category, and every one is reported at a path the catch-all would
	// answer identically — so if they were probed, they would be dropped.
	in := []events.RawFinding{
		{FindingType: "nikto-missing-hsts", TargetURL: srv.URL + "/"},
		{FindingType: "nikto-robots-listed-path", TargetURL: srv.URL + "/ftp/"},
		{FindingType: "nikto-disclosed-header-via", TargetURL: srv.URL + "/"},
		{FindingType: "nikto-sql-injection", TargetURL: srv.URL + "/login.php"},
		{FindingType: "nikto-999001", TargetURL: srv.URL + "/anything"},
	}
	out := runVerify(t.Context(), in)

	assert.Equal(t, in, out, "non-existence findings must pass through untouched")
	assert.Zero(t, srv.hitCount(), "no candidates means no requests at all")
}

// TestVerify_ControlProbeFailureKeepsTheFinding is the fail-open
// decision, stated as a test because it is a deliberate choice and not a
// fallback: we only ever drop on positive evidence.
func TestVerify_ControlProbeFailureKeepsTheFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The reported path answers normally; the control path drops the
		// connection, which is what a rate limiter or a firewall looks
		// like from here.
		if r.URL.Path != "/public/" {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		_, _ = w.Write([]byte(shellBody))
	}))
	t.Cleanup(srv.Close)

	out := runVerify(t.Context(), []events.RawFinding{existenceFinding(srv.URL, "/public/")})

	require.Len(t, out, 1,
		"a control probe that fails proves nothing, so the scanner's conclusion stands")
}

// TestVerify_TargetProbeFailureKeepsTheFinding is the other half of
// fail-open: if we cannot re-fetch the reported path, we have no
// comparison to make.
func TestVerify_TargetProbeFailureKeepsTheFinding(t *testing.T) {
	srv := newCatchAllServer(t, nil)
	dead := srv.URL
	srv.Close() // nothing is listening now; connections are refused

	out := runVerify(t.Context(), []events.RawFinding{existenceFinding(dead, "/public/")})

	require.Len(t, out, 1, "an unreachable target keeps every finding")
}

// TestVerify_StatusDifferenceKeepsTheFinding covers a protected parent
// directory: the control comes back 403 while the reported path is 200,
// so there is no evidence of a catch-all.
func TestVerify_StatusDifferenceKeepsTheFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/backup/" {
			w.WriteHeader(http.StatusForbidden)
		}
		_, _ = w.Write([]byte(shellBody))
	}))
	t.Cleanup(srv.Close)

	out := runVerify(t.Context(), []events.RawFinding{existenceFinding(srv.URL, "/admin/backup/")})

	require.Len(t, out, 1, "identical bodies under different statuses are not a match")
}

// TestVerify_RedirectsAreNotFollowed guards the CheckRedirect setting.
// Without it the reported path's 302 would be chased to the page the
// control also returns, and a real redirect would read as a catch-all.
func TestVerify_RedirectsAreNotFollowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/public/" {
			http.Redirect(w, r, "/landing", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte(shellBody))
	}))
	t.Cleanup(srv.Close)

	out := runVerify(t.Context(), []events.RawFinding{existenceFinding(srv.URL, "/public/")})

	require.Len(t, out, 1,
		"a 302 is compared as a 302, not as whatever it points at")
}

// TestVerify_ExpiredContextChangesNothing pins the PostProcess contract:
// a hook handed a dead ctx returns its input, and does not treat the
// expiry as a result.
func TestVerify_ExpiredContextChangesNothing(t *testing.T) {
	srv := newCatchAllServer(t, nil)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	in := []events.RawFinding{existenceFinding(srv.URL, "/public/")}
	out := runVerify(ctx, in)

	assert.Equal(t, in, out, "an exhausted budget keeps every finding")
	assert.Zero(t, srv.hitCount(), "and issues no requests")
}

// TestVerify_ControlProbeIsSharedWithinABucket pins the memoisation
// that makes this N+1 rather than 2N.
func TestVerify_ControlProbeIsSharedWithinABucket(t *testing.T) {
	srv := newCatchAllServer(t, map[string]string{
		"/ftp/": genuineBody, "/pub/": genuineBody, "/old/": genuineBody,
	})

	out := runVerify(t.Context(), []events.RawFinding{
		existenceFinding(srv.URL, "/ftp/"),
		existenceFinding(srv.URL, "/pub/"),
		existenceFinding(srv.URL, "/old/"),
	})

	require.Len(t, out, 3)
	assert.Equal(t, 4, srv.hitCount(),
		"three reported paths plus ONE shared directory control, not three controls; paths hit: %v",
		srv.pathsHit())
}

// TestVerify_ControlPathMirrorsTheFindingsBucket checks that the control
// actually lands in the right routing class, by observing which path the
// server was asked for.
func TestVerify_ControlPathMirrorsTheFindingsBucket(t *testing.T) {
	srv := newCatchAllServer(t, map[string]string{
		"/.htpasswd": genuineBody, "/db.sql": genuineBody, "/cgi-bin/admin": genuineBody,
	})

	runVerify(t.Context(), []events.RawFinding{
		existenceFinding(srv.URL, "/.htpasswd"),
		existenceFinding(srv.URL, "/db.sql"),
		existenceFinding(srv.URL, "/cgi-bin/admin"),
	})

	var dotfile, ext, none bool
	for _, p := range srv.pathsHit() {
		base := p[strings.LastIndex(p, "/")+1:]
		switch {
		case strings.HasPrefix(base, ".") && base != ".htpasswd":
			dotfile = true
		case strings.HasSuffix(base, ".sql") && base != "db.sql":
			ext = true
		case strings.HasPrefix(p, "/cgi-bin/") && base != "admin" && !strings.Contains(base, "."):
			none = true
		}
	}
	assert.True(t, dotfile, "a dotfile finding needs a dotfile control; paths hit: %v", srv.pathsHit())
	assert.True(t, ext, "a .sql finding needs a .sql control; paths hit: %v", srv.pathsHit())
	assert.True(t, none, "an extensionless finding needs a sibling in its own directory; paths hit: %v", srv.pathsHit())
}

// TestControlURLFor_MirrorsNiktoBuckets pins the bucket derivation
// against Nikto's get_ext (nikto_core.plugin:179), which it mirrors
// rather than reinvents.
func TestControlURLFor_MirrorsNiktoBuckets(t *testing.T) {
	const n = "cafebabe"
	for _, tc := range []struct {
		name, in, want string
	}{
		{"directory", "https://h/public/", "https://h/" + n + "/"},
		{"nested directory control is a sibling, not a root probe",
			"https://h/admin/backup/", "https://h/admin/" + n + "/"},
		{"dotfile", "https://h/.htpasswd", "https://h/." + n},
		{"nested dotfile", "https://h/config/.env", "https://h/config/." + n},
		{"no extension", "https://h/phpinfo", "https://h/" + n},
		{"extension", "https://h/db.sql", "https://h/" + n + ".sql"},
		{"multi-dot keeps only the last extension", "https://h/backup.tar.gz", "https://h/" + n + ".gz"},
		{"port is carried", "https://h:8443/public/", "https://h:8443/" + n + "/"},
		{"query is dropped from the control", "https://h/x.php?id=1", "https://h/" + n + ".php"},
		// Nikto tests the dotfile pattern BEFORE stripping the query, so
		// this is a DOTFILE and not a "env?x=1" extension.
		{"dotfile wins over query", "https://h/.env?x=1", "https://h/." + n},
		// "..%2f" style probes start with two dots, which Nikto's
		// ^\.[^.%] excludes from DOTFILE.
		{"double dot is not a dotfile", "https://h/..config", "https://h/" + n + ".config"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := controlURLFor(tc.in, n)
			require.True(t, ok, "expected a control path for %q", tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestControlURLFor_RefusesWhatItCannotMirror documents the 2.4% of
// candidates that are undecidable by construction. Each returns false,
// which keeps the finding.
func TestControlURLFor_RefusesWhatItCannotMirror(t *testing.T) {
	for _, in := range []string{
		"https://h/",              // the bare root has no sibling
		"https://h",               // ditto, no path at all
		"https://h/index.html~",   // test 000052: extension is punctuation
		"https://h/sam._",         // test 002085
		"https://h/settings.php+", // test 002283
		"https://h/*.*",           // test 000450
		"not a url at all",
	} {
		_, ok := controlURLFor(in, "cafebabe")
		assert.False(t, ok, "%q must yield no control path so the finding is kept", in)
	}
}

// TestControlNonce_IsRandomPerRun guards the property that makes a drop
// trustworthy: a predictable control path is one a target could serve
// real content at, turning every drop into a kept false positive.
func TestControlNonce_IsRandomPerRun(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		got := controlNonce()
		require.NotEmpty(t, got)
		require.False(t, seen[got], "control nonce repeated across runs: %q", got)
		seen[got] = true
	}
}

// TestVerify_OversizeBodyKeepsTheFinding covers the read cap: a response
// too large to compare is undecidable, not a match.
func TestVerify_OversizeBodyKeepsTheFinding(t *testing.T) {
	big := strings.Repeat("x", verifyMaxBodyBytes+1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(big))
	}))
	t.Cleanup(srv.Close)

	out := runVerify(t.Context(), []events.RawFinding{existenceFinding(srv.URL, "/public/")})

	require.Len(t, out, 1,
		"identical oversize bodies are still undecidable — the cap means we did not compare them")
}

// TestVerify_EmptyBodiesStillCompare guards the nil-vs-empty distinction
// in probeResult: a genuinely empty body is comparable, and only an
// oversize one is not.
func TestVerify_EmptyBodiesStillCompare(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	out := runVerify(t.Context(), []events.RawFinding{existenceFinding(srv.URL, "/public/")})

	assert.Empty(t, out,
		"a server answering every path with an empty 200 is a catch-all like any other")
}

// TestVerify_PreservesOrderAndLeavesKeptFindingsUntouched checks the
// pass only ever removes: no reordering, no field rewriting.
func TestVerify_PreservesOrderAndLeavesKeptFindingsUntouched(t *testing.T) {
	srv := newCatchAllServer(t, map[string]string{"/ftp/": genuineBody})

	in := []events.RawFinding{
		{FindingType: "nikto-missing-hsts", TargetURL: srv.URL + "/", Title: "a"},
		existenceFinding(srv.URL, "/public/"), // dropped
		existenceFinding(srv.URL, "/ftp/"),    // kept
		{FindingType: "nikto-etag-inode-leak", TargetURL: srv.URL + "/", Title: "b"},
	}
	out := runVerify(t.Context(), in)

	require.Len(t, out, 3)
	assert.Equal(t, []events.RawFinding{in[0], in[2], in[3]}, out,
		"surviving findings keep their order and every field")
}

// TestVerify_TruncatedResponseKeepsTheFinding is a regression test for a
// shape found by live verification, not invented: the target declared
// content-length 11323 on its genuine /ftp/ listing and sent 11264
// bytes. Go rejects that (curl tolerates it silently); the probe errors,
// and the finding is kept.
//
// The truncated body here is a PREFIX OF THE CONTROL'S body on purpose.
// A partial read that happens to match the control is the case where
// tolerating the truncation would not merely lose information but
// actively produce a wrong drop, so that is the shape worth pinning —
// having a prefix of a page is not evidence about the whole page.
func TestVerify_TruncatedResponseKeepsTheFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ftp/" {
			w.Header().Set("Content-Length", strconv.Itoa(len(shellBody)+59))
			_, _ = w.Write([]byte(shellBody))
			return
		}
		_, _ = w.Write([]byte(shellBody))
	}))
	t.Cleanup(srv.Close)

	out := runVerify(t.Context(), []events.RawFinding{existenceFinding(srv.URL, "/ftp/")})

	require.Len(t, out, 1,
		"a body that ends before its declared length is not a comparison, so the finding stands")
}

// TestVerify_CompressedResponsesCompareAsPlaintext guards the decision
// to let Go handle content coding. A server that gzips one path and not
// another must still yield a usable comparison.
func TestVerify_CompressedResponsesCompareAsPlaintext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") && r.URL.Path != "/public/" {
			// The control path is gzipped; the reported path is not.
			w.Header().Set("Content-Encoding", "gzip")
			zw := gzip.NewWriter(w)
			_, _ = zw.Write([]byte(shellBody))
			_ = zw.Close()
			return
		}
		_, _ = w.Write([]byte(shellBody))
	}))
	t.Cleanup(srv.Close)

	out := runVerify(t.Context(), []events.RawFinding{existenceFinding(srv.URL, "/public/")})

	assert.Empty(t, out,
		"same plaintext under different content codings is still the same page")
}
