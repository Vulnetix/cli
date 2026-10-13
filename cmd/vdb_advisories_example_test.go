package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// runAdvisoriesExample runs `vulnetix vdb advisories CVE-2021-44228` (the
// documented example, with no -V flag) against a server that answers like the
// production API did: the batched cli.advisories endpoint is empty, and the
// per-vulnerability endpoint carries a recorded real response.
func runAdvisoriesExample(t *testing.T, output string) string {
	t.Helper()
	fixture, err := os.ReadFile("testdata/advisories_CVE-2021-44228.json")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/auth/token"):
			_, _ = w.Write([]byte(`{"token":"test-token"}`))
		case strings.Contains(r.URL.Path, "cli.advisories"):
			_, _ = w.Write([]byte(`{"data":{"advisoriesByVuln":{}}}`))
		case strings.HasSuffix(r.URL.Path, "/vuln/CVE-2021-44228/advisories"):
			_, _ = w.Write(fixture)
		default:
			t.Logf("unexpected request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("VULNETIX_API_KEY", "")
	t.Setenv("VULNETIX_API_TOKEN", "")
	t.Chdir(t.TempDir())
	oldURL, oldOrg, oldKey, oldVer, oldOut, oldCache, oldComm, oldCreds := vdbBaseURL, vdbOrgID, vdbSecretKey, vdbAPIVersion, vdbOutput, vdbNoCache, vdbNoCommunity, vdbCreds
	t.Cleanup(func() {
		vdbBaseURL, vdbOrgID, vdbSecretKey, vdbAPIVersion, vdbOutput, vdbNoCache, vdbNoCommunity, vdbCreds = oldURL, oldOrg, oldKey, oldVer, oldOut, oldCache, oldComm, oldCreds
	})
	vdbBaseURL, vdbOrgID, vdbSecretKey = srv.URL, "00000000-0000-0000-0000-000000000000", "test"
	vdbAPIVersion, vdbOutput, vdbNoCache, vdbNoCommunity, vdbCreds = "", output, true, true, nil

	c := &cobra.Command{Use: "advisories"}
	c.SetOut(io.Discard)
	return captureStdout(t, func() {
		if err := v2AdvisoriesCmd.RunE(c, []string{"CVE-2021-44228"}); err != nil {
			t.Errorf("vdb advisories CVE-2021-44228 failed: %v", err)
		}
	})
}

// The reported bug: the documented example printed "Advisories for" and then
// "No advisories found" for Log4Shell, which has many.
func TestVDBAdvisoriesExampleShowsTheAdvisories(t *testing.T) {
	out := runAdvisoriesExample(t, "pretty")
	for _, want := range []string{"Advisories for CVE-2021-44228", "Red Hat advisories", "RHSA-"} {
		if !strings.Contains(out, want) {
			t.Errorf("pretty output is missing %q:\n%s", want, out)
		}
	}
	for _, bad := range []string{"No advisories found", "No advisories were returned"} {
		if strings.Contains(out, bad) {
			t.Errorf("pretty output claims there are no advisories (%q):\n%s", bad, out)
		}
	}
}

func TestVDBAdvisoriesExampleJSONCarriesTheData(t *testing.T) {
	out := runAdvisoriesExample(t, "json")
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if got["identifier"] != "CVE-2021-44228" {
		t.Errorf("identifier = %v", got["identifier"])
	}
	if rh, _ := got["redhatAdvisories"].([]any); len(rh) == 0 {
		t.Errorf("the JSON dropped the advisories: %v", got)
	}
}
