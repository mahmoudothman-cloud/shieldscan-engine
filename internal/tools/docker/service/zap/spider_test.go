package zap

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/odyssey/shieldscan-engine/internal/tools/docker/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSpiderConfigFor_DepthMapping(t *testing.T) {
	cases := []struct {
		depth         string
		maxRPS        int
		wantMaxDepth  int
		wantMaxKids   int
		wantThreadCnt int
	}{
		{"quick", 0, 3, 50, 5},
		{"standard", 0, 5, 200, 10},
		{"deep", 0, 8, 500, 20},
		{"", 0, 5, 200, 10}, // default
		{"unknown", 0, 5, 200, 10},
		{"quick", 3, 3, 50, 3},    // MaxRPS clamps below mode default
		{"deep", 100, 8, 500, 20}, // MaxRPS exceeds cap → cap wins
	}
	for _, tc := range cases {
		t.Run(tc.depth, func(t *testing.T) {
			sc := spiderConfigFor(tc.depth, tc.maxRPS)
			assert.Equal(t, tc.wantMaxDepth, sc.maxDepth)
			assert.Equal(t, tc.wantMaxKids, sc.maxChildren)
			assert.Equal(t, tc.wantThreadCnt, sc.threadCount)
		})
	}
}

func newStubClient(t *testing.T, stub *stubZAPServer) *service.Client {
	t.Helper()
	return &service.Client{
		BaseURL:    stub.URL(),
		HTTPClient: &http.Client{Timeout: 0},
		AuthFunc:   zapQueryParamAuth(stubAPIKey),
		Log:        noopLog(),
	}
}

func TestRunSpider_HappyPath(t *testing.T) {
	stub := newStubZAPServer(t)
	c := newStubClient(t, stub)
	scanID, err := runSpider(context.Background(), c, "https://example.com/",
		spiderConfig{maxDepth: 3, maxChildren: 50, maxDuration: 30 * time.Second, threadCount: 5})
	require.NoError(t, err)
	assert.Equal(t, "0", scanID)
	assert.Equal(t, "https://example.com/", stub.lastSpiderURL)
}

func TestRunSpider_StatusPredicate(t *testing.T) {
	cases := []struct {
		body string
		want bool
	}{
		{`{"status":"100"}`, true},
		{`{"status":"50"}`, false},
		{`{"status":"0"}`, false},
	}
	for _, tc := range cases {
		t.Run(tc.body, func(t *testing.T) {
			done, err := spiderStatusPredicate([]byte(tc.body))
			require.NoError(t, err)
			assert.Equal(t, tc.want, done)
		})
	}
}

func TestWaitForPassiveScanDrain_HappyPath(t *testing.T) {
	stub := newStubZAPServer(t)
	stub.passiveRecords = "0"
	c := newStubClient(t, stub)
	err := waitForPassiveScanDrain(context.Background(), c, 10*time.Second)
	require.NoError(t, err)
}
