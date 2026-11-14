package nmap

import (
	"github.com/rs/zerolog"

	"github.com/odyssey/shieldscan-engine/internal/tools"
)

// NativeConfig configures the subprocess (non-Docker) Nmap runner used
// by the on-prem agent (M14, cmd/agent). The cloud worker keeps the
// warm-pool DockerRunner in nmap.go; both share buildArgs + parseOutput,
// so a finding looks the same whichever side produced it.
type NativeConfig struct {
	// BinaryPath is the resolved nmap binary (PATH or SHIELDSCAN_TOOLS_DIR).
	BinaryPath string
	// AllowPrivateTargets / AllowLoopback widen the Layer-3 target
	// validation for an agent inside the customer's network. See
	// validateOpts.
	AllowPrivateTargets bool
	AllowLoopback       bool
}

// NewNativeRunner returns an Nmap ToolRunner that execs the local
// binary. Same argv as the Docker runner minus the leading "nmap"
// (NativeRunner supplies the binary itself).
func NewNativeRunner(cfg NativeConfig, _ zerolog.Logger) *tools.NativeRunner {
	opts := validateOpts{allowPrivate: cfg.AllowPrivateTargets, allowLoopback: cfg.AllowLoopback}
	return &tools.NativeRunner{
		ToolName:     "nmap",
		ToolCategory: "recon",
		BinaryPath:   cfg.BinaryPath,
		Timeout:      RunnerTimeout,
		Preflight: func(target tools.Target, sc tools.ScanConfig) error {
			return validateTargetOpts(target, sc, opts)
		},
		BuildArgs: func(target tools.Target, sc tools.ScanConfig) []string {
			args, err := buildArgsOpts(target, sc, opts)
			if err != nil || len(args) == 0 {
				return nil
			}
			return args[1:] // drop the "nmap" argv[0] the Docker shape carries
		},
		ParseOutput:     parseOutputForDocker,
		MaxStdoutBytes:  tools.DefaultMaxStdoutBytes,
		ExitCodeLenient: false,
	}
}
