package zap

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/odyssey/shieldscan-engine/internal/tools/docker/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestZapQueryParamAuth_InjectsApikeyAndHost(t *testing.T) {
	auth := zapQueryParamAuth("k1")
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"http://localhost:18080/JSON/core/view/version/", nil)
	require.NoError(t, err)
	auth(req)
	assert.Equal(t, "zap", req.Host, "V0: Host header MUST be set to zap")
	assert.Equal(t, "k1", req.URL.Query().Get("apikey"))
}

func TestZapQueryParamAuth_PreservesExistingQuery(t *testing.T) {
	auth := zapQueryParamAuth("k1")
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"http://localhost:18080/JSON/spider/action/scan/?url=https%3A%2F%2Fa.com&maxChildren=10", nil)
	require.NoError(t, err)
	auth(req)
	q := req.URL.Query()
	assert.Equal(t, "k1", q.Get("apikey"))
	assert.Equal(t, "https://a.com", q.Get("url"))
	assert.Equal(t, "10", q.Get("maxChildren"))
}

func TestZapQueryParamAuth_EmptyKey_StillSetsHost(t *testing.T) {
	auth := zapQueryParamAuth("")
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"http://localhost:18080/JSON/core/view/version/", nil)
	auth(req)
	assert.Equal(t, "zap", req.Host)
	assert.Empty(t, req.URL.Query().Get("apikey"))
}

func TestParseCookieData(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []cookiePair
	}{
		{"single", "s=v", []cookiePair{{"s", "v"}}},
		{"multi", "a=1; b=2; c=3", []cookiePair{{"a", "1"}, {"b", "2"}, {"c", "3"}}},
		{"with spaces", "  a = 1 ;  b = 2  ", []cookiePair{{"a", "1"}, {"b", "2"}}},
		{"empty pair skipped", "a=1;;b=2", []cookiePair{{"a", "1"}, {"b", "2"}}},
		{"no equals skipped", "a=1; novalue; b=2", []cookiePair{{"a", "1"}, {"b", "2"}}},
		{"empty input", "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseCookieData(tc.in)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestApplyCookieAuth_DispatchesHTTPSessionsCalls(t *testing.T) {
	stub := newStubZAPServer(t)
	c := &service.Client{
		BaseURL:    stub.URL(),
		HTTPClient: &http.Client{Timeout: 0},
		AuthFunc:   zapQueryParamAuth(stubAPIKey),
		Log:        noopLog(),
	}
	session, err := applyCookieAuth(context.Background(), c,
		"https://example.com/", "session=abc; csrf=xyz")
	require.NoError(t, err)
	assert.Equal(t, "shieldscan-session", session)
	assert.Equal(t, int32(1), stub.createSessionCalls.Load())
	assert.Equal(t, int32(2), stub.setTokenCalls.Load())
}

func TestApplyCookieAuth_EmptyData_NoOp(t *testing.T) {
	stub := newStubZAPServer(t)
	c := &service.Client{
		BaseURL:    stub.URL(),
		HTTPClient: &http.Client{Timeout: 0},
		AuthFunc:   zapQueryParamAuth(stubAPIKey),
		Log:        noopLog(),
	}
	session, err := applyCookieAuth(context.Background(), c, "https://example.com/", "")
	require.NoError(t, err)
	assert.Equal(t, "", session)
	assert.Equal(t, int32(0), stub.createSessionCalls.Load())
}

func TestExtraArgsAuthMap_Filters(t *testing.T) {
	cfg := tools.ScanConfig{
		ExtraArgs: map[string]string{
			"zap.auth.login_url":          "https://app/login",
			"zap.auth.login_request_data": "u={%username%}&p={%password%}",
			"zap.scan_policy":             "API",
			"unrelated":                   "x",
		},
	}
	got := extraArgsAuthMap(cfg)
	require.Len(t, got, 2)
	assert.Equal(t, "https://app/login", got["login_url"])
	assert.Contains(t, got["login_request_data"], "username")
	for k := range got {
		assert.False(t, strings.HasPrefix(k, "zap.auth."), "prefix should be stripped from %q", k)
	}
}

func TestExtraArgsAuthMap_Empty(t *testing.T) {
	assert.Nil(t, extraArgsAuthMap(tools.ScanConfig{}))
	assert.Nil(t, extraArgsAuthMap(tools.ScanConfig{ExtraArgs: map[string]string{"unrelated": "x"}}))
}
