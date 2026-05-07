// Package nmap provides the Nmap DockerRunner consumer for the
// shieldscan engine. Nmap performs TCP connect scans with service
// and version detection (-sT -sV); output is XML parsed via Go's
// encoding/xml standard library; one RawFinding emits per open port
// at Informational severity with full service/product/version
// metadata preserved.
//
// Per ADR-026 (DockerRunner framework + lazy warm pool — M7 container
// lifecycle architecture) and Task 7.2 design doc
// (plans/2026-05-06-task-7.2-nmap-design.md in shieldscan-docs).
package nmap

import (
	"errors"
	"fmt"

	"github.com/odyssey/shieldscan-engine/internal/tools"
)

// buildArgs constructs the Nmap CLI argument vector for a scan.
// Validates target via Layer 3 defense-in-depth before constructing
// command; Layer 1 (shieldscan-api scan-job ownership validation)
// is required precondition.
//
// Final command shape:
//
//	nmap -sT -sV -oX - -T4 --host-timeout 25m [-p <range>] <target>
func buildArgs(target tools.Target, cfg tools.ScanConfig) ([]string, error) {
	if err := validateTarget(target, cfg); err != nil {
		return nil, fmt.Errorf("nmap: target validation: %w", err)
	}

	addr := target.URL
	if addr == "" {
		return nil, errors.New("nmap: target URL required")
	}

	args := []string{
		"nmap",
		"-sT",
		"-sV",
		"-oX", "-",
		"-T4",
		"--host-timeout", "25m",
	}

	if portRange := portsFromConfig(cfg); portRange != "" {
		args = append(args, "-p", portRange)
	}

	args = append(args, addr)
	return args, nil
}

// portsFromConfig translates cfg.Ports to the Nmap -p argument value.
// Returns empty string for default-top-1000 behavior (Nmap omits -p);
// returns explicit port specs ("80,443", "1-65535") as-is.
//
// Recognized aliases:
//
//	"" or "top-1000" → "" (Nmap default)
//
// For v1, only the top-1000 default + explicit port specs are
// supported. The "top-100"/-F path is forward-pinned for additive
// enhancement.
func portsFromConfig(cfg tools.ScanConfig) string {
	switch cfg.Ports {
	case "", "top-1000":
		return ""
	default:
		return cfg.Ports
	}
}
