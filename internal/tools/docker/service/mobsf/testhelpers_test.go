package mobsf

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/rs/zerolog"
)

const stubAPIKey = "stub-mobsf-key-abc"

// noopLog returns a zerolog.Logger that discards output for tests.
func noopLog() zerolog.Logger {
	return zerolog.Nop()
}

// stubMobSFServer is an httptest.Server simulating MobSF v4.4.6 REST
// API per Phase 0 V4 grounded reality:
//
//   - POST /api/v1/upload       → uploadResponse (hash, scan_type, file_name)
//   - POST /api/v1/scan         → scanResponse
//   - POST /api/v1/report_json  → CANNED v4.4.6 report (sample)
//   - POST /api/v1/delete_scan  → {"deleted":"yes"}
//
// Auth: X-Mobsf-Api-Key header required; non-matching keys → 401.
type stubMobSFServer struct {
	mu sync.Mutex

	server *httptest.Server

	uploadCalls atomic.Int32
	scanCalls   atomic.Int32
	reportCalls atomic.Int32
	deleteCalls atomic.Int32

	lastUploadName string
	lastScanHash   string

	// override report bytes; defaults to phase0SampleReport
	reportBody []byte

	// inject failures
	failNext map[string]int // path → 5xx remaining
}

func newStubMobSFServer(t *testing.T) *stubMobSFServer {
	t.Helper()
	s := &stubMobSFServer{
		reportBody: phase0SampleReport(),
		failNext:   map[string]int{},
	}
	s.server = httptest.NewServer(http.HandlerFunc(s.handle))
	t.Cleanup(s.server.Close)
	return s
}

func (s *stubMobSFServer) URL() string { return s.server.URL }

func (s *stubMobSFServer) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get(APIKeyHeader) != stubAPIKey {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	s.mu.Lock()
	if remaining := s.failNext[r.URL.Path]; remaining > 0 {
		s.failNext[r.URL.Path] = remaining - 1
		s.mu.Unlock()
		http.Error(w, `{"error":"injected"}`, http.StatusInternalServerError)
		return
	}
	s.mu.Unlock()

	switch r.URL.Path {
	case "/api/v1/upload":
		s.uploadCalls.Add(1)
		// Parse multipart to capture file name
		if err := r.ParseMultipartForm(50 << 20); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fhs := r.MultipartForm.File["file"]
		if len(fhs) > 0 {
			s.mu.Lock()
			s.lastUploadName = fhs[0].Filename
			s.mu.Unlock()
		}
		writeJSON(w, uploadResponse{
			Hash:     "stubhash123",
			ScanType: "apk",
			FileName: s.lastUploadName,
		})
	case "/api/v1/scan":
		s.scanCalls.Add(1)
		_ = r.ParseForm()
		s.mu.Lock()
		s.lastScanHash = r.PostForm.Get("hash")
		s.mu.Unlock()
		writeJSON(w, scanResponse{
			ScanType: r.PostForm.Get("scan_type"),
			FileName: r.PostForm.Get("file_name"),
			Hash:     r.PostForm.Get("hash"),
			Version:  "4.4.6",
		})
	case "/api/v1/report_json":
		s.reportCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(s.reportBody)
	case "/api/v1/delete_scan":
		s.deleteCalls.Add(1)
		writeJSON(w, map[string]string{"deleted": "yes"})
	default:
		http.NotFound(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// phase0SampleReport returns a CANNED MobSF v4.4.6 report_json body
// modelled after the Phase 0 DIVA execution sample. Exercises:
//   - code_analysis files-dict shape (D1)
//   - ref key (D2)
//   - owasp-mobile colon form (D3)
//   - masvs full form (D4)
//   - lowercase severity (V5)
//   - manifest_analysis manifest_findings (V11)
//   - permissions dict-keyed (V12)
//   - secrets list-of-strings (V15)
//   - certificate_analysis list-of-3-element-lists (V17)
//   - binary_analysis list-of-objects with sub-checks (V14)
//   - network_security empty (V13 forward-pin)
//   - trackers empty (V16 forward-pin)
func phase0SampleReport() []byte {
	return []byte(`{
  "app_name": "Diva",
  "package_name": "jakhar.aseem.diva",
  "version_name": "1.0",
  "version_code": "1",
  "hash": "stubhash123",
  "file_name": "diva-beta.apk",
  "code_analysis": {
    "findings": {
      "android_sql_raw_query": {
        "files": {
          "jakhar/aseem/diva/SQLInjectionActivity.java": "10,42"
        },
        "metadata": {
          "id": "android_sql_raw_query",
          "description": "App uses raw SQL queries; vulnerable to SQLi.",
          "severity": "high",
          "cvss": 7.5,
          "cwe": "CWE-89: Improper Neutralization of Special Elements",
          "owasp-mobile": "M7: Client Code Quality",
          "masvs": "MSTG-STORAGE-2",
          "ref": null
        }
      },
      "android_logging": {
        "files": {
          "jakhar/aseem/diva/LogActivity.java": "5,8,12"
        },
        "metadata": {
          "id": "android_logging",
          "description": "App logs sensitive data.",
          "severity": "warning",
          "cvss": 0,
          "cwe": "CWE-532: Insertion of Sensitive Information into Log File",
          "owasp-mobile": "M2: Insecure Data Storage",
          "masvs": "MSTG-STORAGE-3",
          "ref": "https://example.com/logging-ref"
        }
      },
      "android_temp_file": {
        "files": {
          "jakhar/aseem/diva/NotesProvider.java": "10,11"
        },
        "metadata": {
          "id": "android_temp_file",
          "description": "Temp file usage.",
          "severity": "info",
          "cvss": 0,
          "cwe": "",
          "owasp-mobile": "",
          "masvs": "",
          "ref": null
        }
      },
      "android_secure_check": {
        "files": {
          "jakhar/aseem/diva/Secure.java": "1"
        },
        "metadata": {
          "severity": "secure"
        }
      }
    }
  },
  "manifest_analysis": {
    "manifest_findings": [
      {
        "rule": "exported_activity",
        "title": "Exported activity",
        "severity": "high",
        "description": "Activity exported without permission.",
        "name": "MainActivity",
        "component": ["activity#MainActivity"]
      },
      {
        "rule": "secure_thing",
        "title": "Secure thing",
        "severity": "secure",
        "description": "no finding",
        "name": "x",
        "component": []
      }
    ]
  },
  "permissions": {
    "android.permission.READ_CONTACTS": {
      "status": "dangerous",
      "info": "Allows the app to read your contacts data.",
      "description": "read contacts"
    },
    "android.permission.INTERNET": {
      "status": "normal",
      "info": "internet",
      "description": "n"
    }
  },
  "network_security": {
    "network_findings": []
  },
  "binary_analysis": [
    {
      "name": "libnative.so",
      "nx": {"status": "info", "severity": "info", "description": "NX bit not enabled"},
      "pie": {"status": "secure", "severity": "info", "description": "PIE enabled"},
      "stack_canary": {"status": "high", "severity": "high", "description": "Stack canary missing"}
    }
  ],
  "secrets": [
    "pkey : notespin",
    ""
  ],
  "certificate_analysis": {
    "certificate_findings": [
      ["warning", "Self-signed certificate", "Certificate is self-signed"],
      ["info", "SHA-256 fingerprint", "abcdef0123"],
      ["x"]
    ]
  },
  "trackers": {
    "trackers": []
  }
}`)
}

// fakeFetcher is the test r2Fetcher injection. Fetch writes a small
// dummy file at staging path and returns it; cleanup removes it.
type fakeFetcher struct {
	fetchCalls atomic.Int32
	body       []byte
	failOnce   bool
}

func (f *fakeFetcher) Fetch(_ context.Context, uploadRef string) (string, func(), error) {
	f.fetchCalls.Add(1)
	if f.failOnce {
		f.failOnce = false
		return "", nil, errFakeFetcher
	}
	dir, err := os.MkdirTemp("", "mobsf-test-fetcher-*")
	if err != nil {
		return "", nil, err
	}
	// derive a filename ending matching the upload ref so extension
	// routing tests work.
	name := uploadRefBasename(uploadRef)
	if name == "" {
		name = "test.apk"
	}
	p := dir + string(os.PathSeparator) + name
	body := f.body
	if body == nil {
		body = []byte("FAKE-APK-BYTES")
	}
	if err := os.WriteFile(p, body, 0o600); err != nil {
		_ = os.RemoveAll(dir)
		return "", nil, err
	}
	return p, func() { _ = os.RemoveAll(dir) }, nil
}

func uploadRefBasename(ref string) string {
	ref = strings.TrimPrefix(ref, "r2://")
	idx := strings.LastIndex(ref, "/")
	if idx < 0 {
		return ref
	}
	return ref[idx+1:]
}

var errFakeFetcher = errFetcherSentinel{}

type errFetcherSentinel struct{}

func (errFetcherSentinel) Error() string { return "fake fetcher: injected failure" }
