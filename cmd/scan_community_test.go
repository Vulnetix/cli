package cmd

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/vulnetix/cli/v3/pkg/auth"
)

func TestIsUnauthenticatedScan(t *testing.T) {
	orig := vdbCreds
	t.Cleanup(func() { vdbCreds = orig })

	cases := []struct {
		name  string
		creds *auth.Credentials
		want  bool
	}{
		{"nil creds", nil, true},
		{"embedded community creds", auth.CommunityCredentials(), true},
		{"real org creds", &auth.Credentials{OrgID: "real-org", APIKey: "real-key", Method: auth.DirectAPIKey}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vdbCreds = tc.creds
			if got := isUnauthenticatedScan(); got != tc.want {
				t.Errorf("isUnauthenticatedScan() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPrintCommunitySignupReminder(t *testing.T) {
	out := captureStderr(t, printCommunitySignupReminder)
	for _, want := range []string{
		"Snapshots are skipped",
		"Community Plan",
		"https://www.vulnetix.com/vdb-register",
		"vulnetix auth login",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("reminder missing %q; got:\n%s", want, out)
		}
	}
}

// printScanArtifacts must never emit a Snapshot line when no snapshot URL was
// returned (the unauthenticated case, where the server persists nothing).
func TestPrintScanArtifacts_NoSnapshotWhenEmpty(t *testing.T) {
	out := captureStdout(t, func() {
		printScanArtifacts("sbom.json", "sast.sarif", ".vulnetix", "", "", nil, nil)
	})
	if strings.Contains(out, "Snapshot:") {
		t.Errorf("expected no Snapshot line for empty URLs; got:\n%s", out)
	}
	if strings.Contains(out, "VEX:") {
		t.Errorf("expected no VEX line when no VEX was written; got:\n%s", out)
	}

	// Every VEX artefact the run produced is surfaced with the other artefacts.
	withVEX := captureStdout(t, func() {
		printScanArtifacts("sbom.json", "sast.sarif", ".vulnetix", "", "",
			[]string{".vulnetix/vex.openvex.json", ".vulnetix/vex-cbom.openvex.json"}, nil)
	})
	for _, want := range []string{".vulnetix/vex.openvex.json", ".vulnetix/vex-cbom.openvex.json"} {
		if !strings.Contains(withVEX, want) {
			t.Errorf("expected %q in the artefact list; got:\n%s", want, withVEX)
		}
	}
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	defer func() { os.Stderr = orig }()
	fn()
	_ = w.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = orig }()
	fn()
	_ = w.Close()
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}
