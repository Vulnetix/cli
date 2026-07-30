package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSCAWithNoDeclaredDependenciesMakesNoAPICall covers a project whose manifest
// parses cleanly and declares nothing: a go.mod with no require block, a
// package.json with no dependencies, a tooling repo.
//
// The SCA round-trip used to fire regardless of the package count, so an empty
// PURL list went to /v2/cli.sca, the call failed, and the command exited 1 with
// "check credentials, config, and network connectivity" — blaming the user's
// setup for a result that is simply clean. Zero dependencies is a legitimate
// answer, not an error, and there is nothing to ask the VDB about.
//
// The API is pointed at a closed port, so any attempt to call it fails the test
// rather than passing quietly.
func TestSCAWithNoDeclaredDependenciesMakesNoAPICall(t *testing.T) {
	t.Setenv("VULNETIX_API_URL", "http://127.0.0.1:1")

	root := t.TempDir()
	// A go.mod with no requires needs no lockfile, so the build-or-lock gate stays
	// out of the way and the run reaches the SCA stage with zero packages.
	if err := os.WriteFile(filepath.Join(root, "go.mod"),
		[]byte("module example.com/empty\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "main.go"),
		[]byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	resetScanFamilyFlags(t, "sca")
	out, err := executeCommand(t, rootCmd, "sca",
		"--path", root, "--no-analytics", "--no-banner", "--no-progress")
	if err != nil {
		t.Fatalf("sca on a dependency-free project should succeed, got: %v\n%s", err, out)
	}
	for _, forbidden := range []string{
		"cli.sca was unavailable",
		"check credentials",
		"connection refused",
	} {
		if strings.Contains(out, forbidden) {
			t.Errorf("output should not mention %q — no API call is warranted:\n%s", forbidden, out)
		}
	}
}

// TestScanWithNoDeclaredDependenciesSucceeds is the same guarantee through the
// orchestrator, which reaches the SCA stage via a different flag path.
func TestScanWithNoDeclaredDependenciesSucceeds(t *testing.T) {
	t.Setenv("VULNETIX_API_URL", "http://127.0.0.1:1")

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"),
		[]byte(`{"name":"empty","version":"1.0.0"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	resetScanFamilyFlags(t, "scan")
	t.Cleanup(func() { _ = scanCmd.Flags().Set("no-malscan", "false") })
	out, err := executeCommand(t, rootCmd, "scan",
		"--path", root, "--no-malscan", "--no-analytics", "--no-banner", "--no-progress")
	if err != nil {
		t.Fatalf("scan on a dependency-free project should succeed, got: %v\n%s", err, out)
	}
	if strings.Contains(out, "cli.sca was unavailable") {
		t.Errorf("scan attempted an SCA round-trip with no packages:\n%s", out)
	}
}
