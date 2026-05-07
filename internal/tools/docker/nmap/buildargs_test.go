package nmap

import (
	"testing"

	"github.com/odyssey/shieldscan-engine/internal/tools"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildArgs_DefaultPortsOmitsFlag(t *testing.T) {
	target := tools.Target{URL: "example.com"}
	cfg := tools.ScanConfig{}

	args, err := buildArgs(target, cfg)
	require.NoError(t, err)
	assert.NotContains(t, args, "-p", "default ports should not emit -p flag")
}

func TestBuildArgs_TopThousandAliasOmitsFlag(t *testing.T) {
	target := tools.Target{URL: "example.com"}
	cfg := tools.ScanConfig{Ports: "top-1000"}

	args, err := buildArgs(target, cfg)
	require.NoError(t, err)
	assert.NotContains(t, args, "-p")
}

func TestBuildArgs_ExplicitPortRange(t *testing.T) {
	target := tools.Target{URL: "example.com"}
	cfg := tools.ScanConfig{Ports: "80,443"}

	args, err := buildArgs(target, cfg)
	require.NoError(t, err)

	pIdx := indexOf(args, "-p")
	require.GreaterOrEqual(t, pIdx, 0, "-p flag should be present")
	require.Less(t, pIdx, len(args)-1, "-p flag should have a value after it")
	assert.Equal(t, "80,443", args[pIdx+1])
}

func TestBuildArgs_FullPortRange(t *testing.T) {
	target := tools.Target{URL: "example.com"}
	cfg := tools.ScanConfig{Ports: "1-65535"}

	args, err := buildArgs(target, cfg)
	require.NoError(t, err)

	pIdx := indexOf(args, "-p")
	require.GreaterOrEqual(t, pIdx, 0)
	assert.Equal(t, "1-65535", args[pIdx+1])
}

func TestBuildArgs_TargetAppendedLast(t *testing.T) {
	target := tools.Target{URL: "example.com"}
	cfg := tools.ScanConfig{}

	args, err := buildArgs(target, cfg)
	require.NoError(t, err)
	assert.Equal(t, "example.com", args[len(args)-1])
}

func TestBuildArgs_StaticFlagsAlwaysPresent(t *testing.T) {
	target := tools.Target{URL: "example.com"}
	cfg := tools.ScanConfig{}

	args, err := buildArgs(target, cfg)
	require.NoError(t, err)

	for _, expected := range []string{"-sT", "-sV", "-oX", "-T4", "--host-timeout", "25m"} {
		assert.Contains(t, args, expected, "expected flag %q in args", expected)
	}
}

func TestBuildArgs_NmapBinaryFirst(t *testing.T) {
	target := tools.Target{URL: "example.com"}
	cfg := tools.ScanConfig{}

	args, err := buildArgs(target, cfg)
	require.NoError(t, err)
	assert.Equal(t, "nmap", args[0])
}

func TestBuildArgs_HostTimeoutValue(t *testing.T) {
	target := tools.Target{URL: "example.com"}
	cfg := tools.ScanConfig{}

	args, err := buildArgs(target, cfg)
	require.NoError(t, err)

	htIdx := indexOf(args, "--host-timeout")
	require.GreaterOrEqual(t, htIdx, 0)
	assert.Equal(t, "25m", args[htIdx+1])
}

func TestBuildArgs_OXSendsToStdout(t *testing.T) {
	target := tools.Target{URL: "example.com"}
	cfg := tools.ScanConfig{}

	args, err := buildArgs(target, cfg)
	require.NoError(t, err)

	oxIdx := indexOf(args, "-oX")
	require.GreaterOrEqual(t, oxIdx, 0)
	assert.Equal(t, "-", args[oxIdx+1], "-oX value must be - (stdout)")
}

func TestBuildArgs_RejectsInvalidTarget(t *testing.T) {
	target := tools.Target{URL: "127.0.0.1"}
	cfg := tools.ScanConfig{}

	_, err := buildArgs(target, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "target validation")
}

func TestBuildArgs_RejectsEmptyTarget(t *testing.T) {
	target := tools.Target{URL: ""}
	cfg := tools.ScanConfig{}

	_, err := buildArgs(target, cfg)
	require.Error(t, err)
}

func TestPortsFromConfig_Default(t *testing.T) {
	assert.Equal(t, "", portsFromConfig(tools.ScanConfig{}))
}

func TestPortsFromConfig_TopThousand(t *testing.T) {
	assert.Equal(t, "", portsFromConfig(tools.ScanConfig{Ports: "top-1000"}))
}

func TestPortsFromConfig_ExplicitRange(t *testing.T) {
	assert.Equal(t, "1-65535", portsFromConfig(tools.ScanConfig{Ports: "1-65535"}))
}

// indexOf returns the index of needle in haystack, or -1 if not found.
func indexOf(haystack []string, needle string) int {
	for i, s := range haystack {
		if s == needle {
			return i
		}
	}
	return -1
}
