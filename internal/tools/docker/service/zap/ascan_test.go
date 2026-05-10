package zap

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateScanPolicy_Allowlist(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"empty (use default implicitly)", "", false},
		{"Default Policy exact", "Default Policy", false},
		{"API exact (Phase 0 V5/V17 actual)", "API", false},
		{"Pen Test exact", "Pen Test", false},
		{"strength-threshold combo", "St-High-Th-Med", false},
		{"DOC-stale name rejected", "Penetration Tester Policy", true},
		{"DOC-stale 'API Policy' rejected", "API Policy", true},
		{"random string rejected", "Bogus Policy", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateScanPolicy(tc.input)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "not in allowlist")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestZapPolicyAllowlist_Has22Entries(t *testing.T) {
	assert.Len(t, zapPolicyAllowlist, 22, "Phase 0 V5/V17: ZAP 2.17.0 ships 22 policies")
}

func TestRunActiveScan_HappyPath(t *testing.T) {
	stub := newStubZAPServer(t)
	c := newStubClient(t, stub)
	scanID, err := runActiveScan(context.Background(), c, "https://example.com/",
		ascanConfig{scanPolicyName: "", maxDuration: 30 * time.Second})
	require.NoError(t, err)
	assert.Equal(t, "0", scanID)
	assert.Equal(t, "https://example.com/", stub.lastAscanURL)
	assert.Equal(t, "", stub.lastPolicyArg, "empty policy → omit param")
}

func TestRunActiveScan_PolicyForwarded(t *testing.T) {
	stub := newStubZAPServer(t)
	c := newStubClient(t, stub)
	_, err := runActiveScan(context.Background(), c, "https://example.com/",
		ascanConfig{scanPolicyName: "Pen Test", maxDuration: 30 * time.Second})
	require.NoError(t, err)
	assert.Equal(t, "Pen Test", stub.lastPolicyArg)
}

func TestRunActiveScan_RejectsOutOfAllowlist(t *testing.T) {
	stub := newStubZAPServer(t)
	c := newStubClient(t, stub)
	_, err := runActiveScan(context.Background(), c, "https://example.com/",
		ascanConfig{scanPolicyName: "Penetration Tester Policy"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not in allowlist")
	assert.Equal(t, int32(0), stub.ascanScanCalls.Load(), "scan must NOT be triggered on allowlist reject")
}

func TestAscanDuration_DepthMapping(t *testing.T) {
	assert.Equal(t, 10*time.Minute, ascanDuration("quick"))
	assert.Equal(t, 30*time.Minute, ascanDuration("standard"))
	assert.Equal(t, 90*time.Minute, ascanDuration("deep"))
	assert.Equal(t, 30*time.Minute, ascanDuration(""))
}
