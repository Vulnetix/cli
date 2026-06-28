package cmd

import (
	"runtime/debug"
	"testing"
)

func TestModuleVersionFromDeps(t *testing.T) {
	deps := []*debug.Module{
		{Path: "github.com/vulnetix/malscan-engine", Version: "v0.5.3"},
		{Path: "github.com/Vulnetix/vdb-cyclonedx", Version: "v0.2.0"},
		{Path: "github.com/open-policy-agent/opa", Version: "v1.17.0"},
	}

	for _, tc := range []struct {
		path string
		want string
	}{
		{path: "github.com/vulnetix/malscan-engine", want: "v0.5.3"},
		{path: "github.com/Vulnetix/vdb-cyclonedx", want: "v0.2.0"},
		{path: "github.com/open-policy-agent/opa", want: "v1.17.0"},
		{path: "example.com/not-a-real-dependency", want: "unknown"},
	} {
		if got := moduleVersionFromDeps(tc.path, deps); got != tc.want {
			t.Fatalf("moduleVersionFromDeps(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestModuleVersionFromDepsPrefersReplacementVersion(t *testing.T) {
	deps := []*debug.Module{
		{
			Path:    "example.com/module",
			Version: "v1.0.0",
			Replace: &debug.Module{
				Path:    "example.com/fork",
				Version: "v1.2.0",
			},
		},
	}

	if got := moduleVersionFromDeps("example.com/module", deps); got != "v1.2.0" {
		t.Fatalf("moduleVersionFromDeps replacement = %q, want v1.2.0", got)
	}
}
