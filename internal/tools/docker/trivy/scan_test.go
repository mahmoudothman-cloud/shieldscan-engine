package trivy

import (
	"reflect"
	"strings"
	"testing"

	"github.com/odyssey/shieldscan-engine/internal/tools"
)

func TestBuildArgsImage(t *testing.T) {
	cases := []struct {
		name   string
		target tools.Target
		want   []string
	}{
		{
			name:   "happy path image ref",
			target: tools.Target{URL: "alpine:3.10", TargetType: "container"},
			want: []string{
				"trivy", "image",
				"--format", "json",
				"--scanners", "vuln",
				"--exit-code", "0",
				"alpine:3.10",
			},
		},
		{
			name:   "registry-prefixed image ref",
			target: tools.Target{URL: "ghcr.io/example/app:v1.0.0", TargetType: "container"},
			want: []string{
				"trivy", "image",
				"--format", "json",
				"--scanners", "vuln",
				"--exit-code", "0",
				"ghcr.io/example/app:v1.0.0",
			},
		},
		{
			name:   "digest-pinned image ref pass-through literal",
			target: tools.Target{URL: "alpine@sha256:abcdef0123456789", TargetType: "container"},
			want: []string{
				"trivy", "image",
				"--format", "json",
				"--scanners", "vuln",
				"--exit-code", "0",
				"alpine@sha256:abcdef0123456789",
			},
		},
		{
			name:   "image ref with spaces (literal pass-through; Trivy handles parsing)",
			target: tools.Target{URL: "weird image name", TargetType: "container"},
			want: []string{
				"trivy", "image",
				"--format", "json",
				"--scanners", "vuln",
				"--exit-code", "0",
				"weird image name",
			},
		},
		{
			name:   "empty URL → nil argv (DockerRunner exec error path)",
			target: tools.Target{URL: "", TargetType: "container"},
			want:   nil,
		},
		{
			name:   "fs SourcePath only (cross-mode misuse) → nil argv",
			target: tools.Target{SourcePath: "/scan", TargetType: "container"},
			want:   nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := buildArgsImage(c.target, tools.ScanConfig{})
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("got=%v\nwant=%v", got, c.want)
			}
		})
	}
}

func TestBuildArgsFs(t *testing.T) {
	cases := []struct {
		name   string
		target tools.Target
		want   []string
	}{
		{
			name:   "happy path absolute path",
			target: tools.Target{SourcePath: "/scan-target", TargetType: "source"},
			want: []string{
				"trivy", "fs",
				"--format", "json",
				"--scanners", "vuln",
				"--exit-code", "0",
				"/scan-target",
			},
		},
		{
			name:   "relative path literal pass-through",
			target: tools.Target{SourcePath: "./project", TargetType: "source"},
			want: []string{
				"trivy", "fs",
				"--format", "json",
				"--scanners", "vuln",
				"--exit-code", "0",
				"./project",
			},
		},
		{
			name:   "path with spaces (literal pass-through)",
			target: tools.Target{SourcePath: "/scan path/has spaces", TargetType: "source"},
			want: []string{
				"trivy", "fs",
				"--format", "json",
				"--scanners", "vuln",
				"--exit-code", "0",
				"/scan path/has spaces",
			},
		},
		{
			name:   "empty SourcePath → nil argv",
			target: tools.Target{SourcePath: "", TargetType: "source"},
			want:   nil,
		},
		{
			name:   "URL only (cross-mode misuse) → nil argv",
			target: tools.Target{URL: "alpine:3.10", TargetType: "source"},
			want:   nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := buildArgsFs(c.target, tools.ScanConfig{})
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("got=%v\nwant=%v", got, c.want)
			}
		})
	}
}

// TestBuildArgs_Argv0_TrivyBinary asserts both argv shapes start with
// the binary name "trivy" per Container.Exec convention
// (ContainerExecCreate.Cmd takes full argv including binary).
func TestBuildArgs_Argv0_TrivyBinary(t *testing.T) {
	img := buildArgsImage(tools.Target{URL: "alpine"}, tools.ScanConfig{})
	if len(img) == 0 || img[0] != "trivy" {
		t.Errorf("buildArgsImage argv[0]=%q; want \"trivy\"", strings.Join(img[:1], ""))
	}
	fs := buildArgsFs(tools.Target{SourcePath: "/x"}, tools.ScanConfig{})
	if len(fs) == 0 || fs[0] != "trivy" {
		t.Errorf("buildArgsFs argv[0]=%q; want \"trivy\"", strings.Join(fs[:1], ""))
	}
}

// TestBuildArgs_ExitCodeZero_Y1Flag asserts the --exit-code 0 flag
// pair is present in both argv shapes per Y1 lock (defense-in-depth
// alongside DockerRunner.ExitCodeLenient: true in trivy.go).
func TestBuildArgs_ExitCodeZero_Y1Flag(t *testing.T) {
	for _, args := range [][]string{
		buildArgsImage(tools.Target{URL: "alpine"}, tools.ScanConfig{}),
		buildArgsFs(tools.Target{SourcePath: "/x"}, tools.ScanConfig{}),
	} {
		found := false
		for i := 0; i < len(args)-1; i++ {
			if args[i] == "--exit-code" && args[i+1] == "0" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("argv missing --exit-code 0 pair: %v", args)
		}
	}
}
