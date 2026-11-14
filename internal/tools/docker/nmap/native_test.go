package nmap

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/odyssey/shieldscan-engine/internal/tools"
)

func TestNativeRunner_LoopbackAndPrivateAllowedOnlyWhenOptedIn(t *testing.T) {
	strict := NewNativeRunner(NativeConfig{BinaryPath: "/usr/bin/nmap"}, zerolog.Nop())
	agent := NewNativeRunner(NativeConfig{
		BinaryPath: "/usr/bin/nmap", AllowPrivateTargets: true, AllowLoopback: true,
	}, zerolog.Nop())

	for _, url := range []string{"http://127.0.0.1:3000", "http://10.0.0.5:8080"} {
		assert.Error(t, strict.Preflight(tools.Target{URL: url}, tools.ScanConfig{}), url)
		assert.Nil(t, strict.BuildArgs(tools.Target{URL: url}, tools.ScanConfig{}), url)

		require.NoError(t, agent.Preflight(tools.Target{URL: url}, tools.ScanConfig{}), url)
		args := agent.BuildArgs(tools.Target{URL: url}, tools.ScanConfig{})
		require.NotEmpty(t, args, url)
		assert.NotEqual(t, "nmap", args[0], "argv[0] is the binary, supplied by NativeRunner")
		assert.Equal(t, "-sT", args[0])
	}
	// What neither side may ever scan.
	for _, url := range []string{"http://169.254.169.254", "http://224.0.0.1"} {
		assert.Error(t, agent.Preflight(tools.Target{URL: url}, tools.ScanConfig{}), url)
	}
	assert.Equal(t, "nmap", agent.Name())
	assert.Equal(t, "recon", agent.Category())
}
