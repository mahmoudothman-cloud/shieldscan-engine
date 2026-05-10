package zap

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/odyssey/shieldscan-engine/internal/tools/docker/service"
)

// zapAPIHostHeader is the canonical Host header value ZAP daemon uses
// to disambiguate API requests from proxy requests. Per Phase 0 V0
// finding: ZAP routes Host=localhost:<port> to proxy mode (returns
// HTTP-host-connection-refused error), and Host="zap" to API mode.
// ServiceContainerOpts in Task 7.5b spinup.go does not yet carry
// HostOverride; consumer-local AuthFunc closure sets req.Host instead.
// Forward-pin: framework promotion to ServiceConfig.HostOverride at
// 2nd-instance threshold per Phase 5.D Task 7.5b precedent.
const zapAPIHostHeader = "zap"

// zapQueryParamAuth returns a service.AuthFunc that injects ZAP's
// canonical apikey query parameter into every API request AND sets
// the Host header to "zap" per V0 finding. Per Task 7.3 design doc
// Q7 lock: AuthFunc escape-hatch closure (consumer-local; no
// framework extension; ZAP's documented canonical auth method).
//
// Empty apiKey returns a no-op closure; ZAP container must then be
// configured with -config api.disablekey=true (not recommended in
// production). Q7 lock pins apiKey-required path.
func zapQueryParamAuth(apiKey string) service.AuthFunc {
	return func(req *http.Request) {
		// V0 — Host header MUST be "zap" or ZAP routes the request
		// through its proxy interpreter.
		req.Host = zapAPIHostHeader
		if apiKey == "" {
			return
		}
		q := req.URL.Query()
		q.Set("apikey", apiKey)
		req.URL.RawQuery = q.Encode()
	}
}

// applyCookieAuth injects the AuthConfig.Data cookie string into ZAP's
// httpSessions API for the configured target site. Per Q6 lock cookie
// pass-through path. Cookie format per SPEC §7.1 + AuthConfig.Type
// docstring: "name=value; name2=value2".
//
// Workflow per V18:
//  1. POST /JSON/httpSessions/action/createEmptySession/?site=<host:port>&session=shieldscan-session
//  2. For each cookie: POST /JSON/httpSessions/action/setSessionTokenValue/?site=<host:port>&session=shieldscan-session&sessionToken=<name>&tokenValue=<value>
//  3. Activate session (active session is sticky on the site)
//
// Returns the session name on success (caller may pass to subsequent
// spider/ascan via httpSessions activeSession state).
func applyCookieAuth(ctx context.Context, client *service.Client, targetURL string, cookieData string) (string, error) {
	if cookieData == "" {
		return "", nil
	}
	site, err := extractHostPort(targetURL)
	if err != nil {
		return "", fmt.Errorf("zap auth: extract host:port: %w", err)
	}
	const sessionName = "shieldscan-session"
	createPath := fmt.Sprintf("/JSON/httpSessions/action/createEmptySession/?site=%s&session=%s",
		url.QueryEscape(site), url.QueryEscape(sessionName))
	if _, err := client.Get(ctx, createPath); err != nil {
		return "", fmt.Errorf("zap auth: createEmptySession: %w", err)
	}
	for _, c := range parseCookieData(cookieData) {
		setPath := fmt.Sprintf("/JSON/httpSessions/action/setSessionTokenValue/?site=%s&session=%s&sessionToken=%s&tokenValue=%s",
			url.QueryEscape(site), url.QueryEscape(sessionName),
			url.QueryEscape(c.name), url.QueryEscape(c.value))
		if _, err := client.Get(ctx, setPath); err != nil {
			return "", fmt.Errorf("zap auth: setSessionTokenValue %q: %w", c.name, err)
		}
	}
	return sessionName, nil
}

type cookiePair struct {
	name  string
	value string
}

// parseCookieData splits "name=value; name2=value2" cookie format into
// pairs. Permissive: ignores empty pairs and pairs without '='.
func parseCookieData(data string) []cookiePair {
	if data == "" {
		return nil
	}
	parts := strings.Split(data, ";")
	out := make([]cookiePair, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		eq := strings.IndexByte(p, '=')
		if eq <= 0 {
			continue
		}
		out = append(out, cookiePair{
			name:  strings.TrimSpace(p[:eq]),
			value: strings.TrimSpace(p[eq+1:]),
		})
	}
	return out
}

// extraArgsAuthMap returns the subset of cfg.ExtraArgs with the
// "zap.auth." prefix, with the prefix stripped. Used by the form-based
// escape-hatch path (Q6 lock; v1 power-users carry zap.auth.login_url
// + zap.auth.login_request_data + zap.auth.username + zap.auth.password
// + zap.auth.logged_in_indicator via ExtraArgs).
//
// nil/empty map returns nil. v2 typed-enum AuthConfig.Type expansion
// (form_based, bearer, basic) per design doc forward-pin replaces this.
func extraArgsAuthMap(cfg tools.ScanConfig) map[string]string {
	if len(cfg.ExtraArgs) == 0 {
		return nil
	}
	out := make(map[string]string)
	const prefix = "zap.auth."
	for k, v := range cfg.ExtraArgs {
		if strings.HasPrefix(k, prefix) {
			out[strings.TrimPrefix(k, prefix)] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
