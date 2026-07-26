package cmd

import (
	"strings"
	"testing"
)

func TestUploadPublishableFormats(t *testing.T) {
	for _, f := range []string{"sarif", "cyclonedx", "spdx"} {
		if !uploadPublishable(f) {
			t.Errorf("%s has a typed endpoint and must be publishable", f)
		}
	}
	// These used to be accepted and posted to /v2/cli.upload, which answers
	// 503 in production. Accepting them again would restore a silent no-op.
	for _, f := range []string{"openvex", "csaf_vex", "json", "xml", "unknown", ""} {
		if uploadPublishable(f) {
			t.Errorf("%s has no typed endpoint and must not be publishable", f)
		}
	}
}

// The error a user sees for an unsupported report has to be actionable. The
// old behaviour was an opaque "API error (HTTP 503): file storage not
// configured", which told them nothing they could act on.
func TestUnsupportedFormatErrorIsActionable(t *testing.T) {
	cases := []struct {
		file     string
		wantSubs []string
	}{
		{"sonarqube-issues.json", []string{"sonarqube-issues.json", "SARIF, CycloneDX and SPDX", "sonar.sarifReportPaths"}},
		{"snyk-report.json", []string{"--sarif-file-output"}},
		{"trivy-out.json", []string{"--format sarif"}},
		{"shodan-vulns.json", []string{"SARIF, CycloneDX and SPDX"}},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			err := unsupportedFormatError("/tmp/"+tc.file, "json")
			if err == nil {
				t.Fatal("expected an error")
			}
			for _, sub := range tc.wantSubs {
				if !strings.Contains(err.Error(), sub) {
					t.Errorf("error should mention %q:\n%s", sub, err)
				}
			}
			if strings.Contains(err.Error(), "503") {
				t.Error("the 503 was the symptom, not the explanation")
			}
		})
	}
}

// Republishing a Vulnetix report would mint a second ScannerRun for a scan
// that is already recorded, doubling its findings. Discovery mode walks
// .vulnetix/, so this is the common case, not an edge case.
func TestAlreadyPublishedIsRecognisedAndExplained(t *testing.T) {
	err := alreadyPublishedError("/repo/.vulnetix/sast.sarif", "Vulnetix SAST")
	if !isAlreadyPublished(err) {
		t.Fatal("discovery mode must be able to tell this from a real failure")
	}
	for _, sub := range []string{"sast.sarif", "Vulnetix SAST", "twice", "--no-upload"} {
		if !strings.Contains(err.Error(), sub) {
			t.Errorf("error should mention %q:\n%s", sub, err)
		}
	}
	// A genuine failure must not be swallowed as "already published".
	if isAlreadyPublished(unsupportedFormatError("/tmp/x.json", "json")) {
		t.Error("an unsupported format is a failure, not a skip")
	}
}

func TestSARIFExportHintOnlyWhenKnown(t *testing.T) {
	if h := sarifExportHint("some-internal-tool.json"); h != "" {
		t.Errorf("should not invent a hint: %q", h)
	}
	if h := sarifExportHint("SonarQube-Issues.JSON"); h == "" {
		t.Error("matching should be case-insensitive")
	}
}

// The tally that sets the exit code and the tally that fills --json used to be
// computed separately, and only the first applied --strict. `gha upload
// --strict --json` therefore reported "failed": 0 on a run it had just failed.
func TestStrictAppliesToTheJSONTally(t *testing.T) {
	results := []ghaFileResult{
		{Status: "uploaded"},
		{Status: "skipped"},
		{Status: "skipped"},
		{Status: "error"},
	}

	prev := ghaStrict
	defer func() { ghaStrict = prev }()

	ghaStrict = false
	up, failed, skipped := tallyGHAResults(results)
	if up != 1 || failed != 1 || skipped != 2 {
		t.Errorf("lenient: got %d/%d/%d, want 1 uploaded, 1 failed, 2 skipped", up, failed, skipped)
	}

	ghaStrict = true
	up, failed, skipped = tallyGHAResults(results)
	if up != 1 || failed != 3 || skipped != 0 {
		t.Errorf("strict: got %d/%d/%d, want 1 uploaded, 3 failed, 0 skipped", up, failed, skipped)
	}
}
