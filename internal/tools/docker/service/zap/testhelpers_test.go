package zap

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/rs/zerolog"
)

const stubAPIKey = "stub-key-abc"

// noopLog returns a zerolog.Logger that discards output for tests.
func noopLog() zerolog.Logger {
	return zerolog.Nop()
}

// stubZAPServer returns an httptest.Server simulating a ZAP daemon
// with a canned alert set + spider/ascan endpoints. Per Phase 0 V0:
// validates Host header is "zap" — returns ZAP-error proxy response
// otherwise (mirrors empirical ZAP behavior so tests catch host
// header drift).
//
// Per Phase 0 V6 sample alert structure with cweid as JSON STRING
// (matches empirical ZAP 2.17.0 response).
type stubZAPServer struct {
	mu sync.Mutex

	server *httptest.Server

	// counters surface request behavior to tests
	createSessionCalls atomic.Int32
	setTokenCalls      atomic.Int32
	spiderScanCalls    atomic.Int32
	ascanScanCalls     atomic.Int32
	alertsCalls        atomic.Int32

	// requireHostHeader if true rejects requests with Host != "zap"
	// per Phase 0 V0 finding.
	requireHostHeader bool

	// Captured request data for assertions
	lastSpiderURL string
	lastAscanURL  string
	lastPolicyArg string

	// Configurable response state
	spiderStatus      string // returned for /spider/view/status/
	ascanStatus       string // returned for /ascan/view/status/
	passiveRecords    string // returned for /pscan/view/recordsToScan/
	alerts            []map[string]any
	scanPolicyNames   []string
	versionResponse   map[string]string
	failNextEndpoints map[string]int // path → 5xx count remaining
}

func newStubZAPServer(t *testing.T) *stubZAPServer {
	t.Helper()
	s := &stubZAPServer{
		requireHostHeader: true,
		spiderStatus:      "100",
		ascanStatus:       "100",
		passiveRecords:    "0",
		versionResponse:   map[string]string{"version": "2.17.0-stub"},
		scanPolicyNames: []string{
			"API", "API-Minimal", "Default Policy", "Dev CICD", "Dev Full",
			"Dev Standard", "Pen Test", "QA CICD", "QA Full", "QA Standard",
			"Sequence", "St-High-Th-High", "St-High-Th-Low", "St-High-Th-Med",
			"St-Ins-Th-High", "St-Ins-Th-Low", "St-Ins-Th-Med",
			"St-Low-Th-High", "St-Low-Th-Low", "St-Low-Th-Med",
			"St-Med-Th-High", "St-Med-Th-Low",
		},
		alerts:            sampleAlerts(),
		failNextEndpoints: map[string]int{},
	}
	s.server = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.server.Close)
	return s
}

func (s *stubZAPServer) URL() string { return s.server.URL }

func (s *stubZAPServer) handle(w http.ResponseWriter, r *http.Request) {
	if s.requireHostHeader && r.Host != "zap" {
		// Mirror ZAP daemon's proxy-mode error response shape.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ZAP Error [proxy mode]: Host header was " + r.Host))
		return
	}
	// apikey enforcement intentionally lenient in stub (ZAP is more
	// lenient on view-class endpoints; sufficient for tests). Real
	// ZAP behavior verified empirically at Phase 0 V3.

	s.mu.Lock()
	if remaining, ok := s.failNextEndpoints[r.URL.Path]; ok && remaining > 0 {
		s.failNextEndpoints[r.URL.Path] = remaining - 1
		s.mu.Unlock()
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"injected"}`))
		return
	}
	s.mu.Unlock()

	switch {
	case strings.HasPrefix(r.URL.Path, "/JSON/core/view/version/"):
		writeJSON(w, s.versionResponse)
	case strings.HasPrefix(r.URL.Path, "/JSON/spider/action/scan/"):
		s.spiderScanCalls.Add(1)
		s.mu.Lock()
		s.lastSpiderURL = r.URL.Query().Get("url")
		s.mu.Unlock()
		writeJSON(w, map[string]string{"scan": "0"})
	case strings.HasPrefix(r.URL.Path, "/JSON/spider/view/status/"):
		writeJSON(w, map[string]string{"status": s.spiderStatus})
	case strings.HasPrefix(r.URL.Path, "/JSON/pscan/view/recordsToScan/"):
		writeJSON(w, map[string]string{"recordsToScan": s.passiveRecords})
	case strings.HasPrefix(r.URL.Path, "/JSON/ascan/action/scan/"):
		s.ascanScanCalls.Add(1)
		s.mu.Lock()
		s.lastAscanURL = r.URL.Query().Get("url")
		s.lastPolicyArg = r.URL.Query().Get("scanPolicyName")
		s.mu.Unlock()
		writeJSON(w, map[string]string{"scan": "0"})
	case strings.HasPrefix(r.URL.Path, "/JSON/ascan/action/stop/"):
		writeJSON(w, map[string]string{"Result": "OK"})
	case strings.HasPrefix(r.URL.Path, "/JSON/ascan/view/status/"):
		writeJSON(w, map[string]string{"status": s.ascanStatus})
	case strings.HasPrefix(r.URL.Path, "/JSON/ascan/view/scanPolicyNames/"):
		writeJSON(w, map[string]any{"scanPolicyNames": s.scanPolicyNames})
	case strings.HasPrefix(r.URL.Path, "/JSON/core/view/alerts/"):
		s.alertsCalls.Add(1)
		writeJSON(w, map[string]any{"alerts": s.alerts})
	case strings.HasPrefix(r.URL.Path, "/JSON/httpSessions/action/createEmptySession/"):
		s.createSessionCalls.Add(1)
		writeJSON(w, map[string]string{"Result": "OK"})
	case strings.HasPrefix(r.URL.Path, "/JSON/httpSessions/action/setSessionTokenValue/"):
		s.setTokenCalls.Add(1)
		writeJSON(w, map[string]string{"Result": "OK"})
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not_found"}`))
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// sampleAlerts mirrors the Phase 0 V6 sample alert (CSP-not-set
// against example.com) plus 2 synthetic variations exercising
// V8 (False Positive drop) + V12 (tags extraction).
func sampleAlerts() []map[string]any {
	return []map[string]any{
		{
			"id":          "0",
			"pluginId":    "10038",
			"name":        "Content Security Policy (CSP) Header Not Set",
			"risk":        "Medium",
			"confidence":  "High",
			"description": "CSP missing.",
			"url":         "https://example.com/",
			"method":      "GET",
			"param":       "",
			"attack":      "",
			"evidence":    "",
			"cweid":       "693",
			"wascid":      "15",
			"solution":    "Set CSP header.",
			"reference":   "https://owasp.org/csp\nhttps://web.dev/csp",
			"messageId":   "4",
			"sourceid":    "3",
			"inputVector": "",
			"other":       "",
			"alertRef":    "10038-1",
			"tags": map[string]string{
				"OWASP_2021_A05": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
				"CWE-693":        "https://cwe.mitre.org/data/definitions/693.html",
				"POLICY_PENTEST": "",
				"SYSTEMIC":       "https://systemic",
			},
		},
		{
			"id":          "1",
			"pluginId":    "40012",
			"name":        "Cross Site Scripting (Reflected)",
			"risk":        "High",
			"confidence":  "Medium",
			"description": "XSS reflected.",
			"url":         "https://example.com/search?q=",
			"method":      "GET",
			"param":       "q",
			"attack":      "<script>alert(1)</script>",
			"evidence":    "<script>alert(1)</script>",
			"cweid":       "79",
			"wascid":      "8",
			"solution":    "Encode output.",
			"reference":   "",
			"messageId":   "12",
			"sourceid":    "1",
			"inputVector": "URL_QUERY_STRING_VALUE",
			"other":       "",
			"alertRef":    "40012-1",
			"tags": map[string]string{
				"OWASP_2021_A03": "https://owasp.org/A03",
			},
		},
		{
			"id":          "2",
			"pluginId":    "99999",
			"name":        "Bogus False Positive",
			"risk":        "False Positive", // V8/V9: must be DROPPED by parser
			"confidence":  "Low",
			"description": "Should never reach RawFinding.",
			"url":         "https://example.com/fp",
			"method":      "GET",
			"cweid":       "0",
			"tags":        map[string]string{},
		},
	}
}
