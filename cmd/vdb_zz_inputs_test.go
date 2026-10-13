package cmd

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// vulnCommandPaths lists every vulnerability-keyed command under c.
func vulnCommandPaths(c *cobra.Command) []string {
	var out []string
	for _, sub := range c.Commands() {
		out = append(out, vulnCommandPaths(sub)...)
		if vulnArgUse.MatchString(sub.Use) && sub.RunE != nil {
			out = append(out, sub.CommandPath())
		}
	}
	return out
}

func findCommand(t *testing.T, path string) *cobra.Command {
	t.Helper()
	parts := strings.Fields(path)
	c, _, err := rootCmd.Find(parts[1:])
	if err != nil || c.CommandPath() != path {
		t.Fatalf("no command %q", path)
	}
	return c
}

// Every vulnerability-keyed vdb command must be wrapped. A command registered
// after the wrapping ran (a file sorting after vdb_zz_inputs.go) would silently
// miss the input kinds; this catches it.
func TestEveryVulnCommandTakesInputKinds(t *testing.T) {
	want := vulnCommandPaths(vdbCmd)
	got := append([]string{}, wrappedVulnCommands...)
	sort.Strings(want)
	sort.Strings(got)
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("wrapped %v\nwant %v", got, want)
	}
	if len(got) < 15 {
		t.Fatalf("only %d vulnerability-keyed commands wrapped: %v", len(got), got)
	}
	for _, path := range []string{"vulnetix vdb workarounds", "vulnetix vdb kev get", "vulnetix vdb exploits", "vulnetix vdb fixes"} {
		c := findCommand(t, path)
		for _, name := range []string{"vuln-id", "cpe", "swid", "tei", "cel", "package-version"} {
			if c.Flags().Lookup(name) == nil {
				t.Errorf("%s has no --%s", path, name)
			}
		}
	}
}

// A command's own flag of an input's name keeps its meaning: the wrapper adds
// only the flags a command does not define.
func TestWrapperKeepsACommandsOwnFlags(t *testing.T) {
	c := &cobra.Command{Use: "probe <vuln-id>", RunE: func(*cobra.Command, []string) error { return nil }}
	c.Flags().String("purl", "", "the command's own purl")
	added := addMissingInputFlags(c.Flags(), &inputFlags{})
	for _, n := range added {
		if n == "purl" {
			t.Fatal("the command's own --purl must not be replaced")
		}
	}
	if c.Flags().Lookup("purl").Usage != "the command's own purl" || c.Flags().Lookup("cpe") == nil {
		t.Error("own flag kept, missing input flags added")
	}
}

// A vulnerability id still reaches the command unchanged, with no request.
func TestWrapperPassesAVulnIDStraightThrough(t *testing.T) {
	var got []string
	c := &cobra.Command{Use: "probe <vuln-id>", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
		got = args
		return nil
	}}
	wrapVulnCommand(c)
	c.SetArgs([]string{"CVE-2021-44228"})
	if err := c.Execute(); err != nil || len(got) != 1 || got[0] != "CVE-2021-44228" {
		t.Fatalf("got %v, %v", got, err)
	}
	c.SetArgs([]string{"--vuln-id", "GHSA-jfh8-c2jp-5v3q"})
	if err := c.Execute(); err != nil || got[0] != "GHSA-jfh8-c2jp-5v3q" {
		t.Fatalf("--vuln-id alone: %v, %v", got, err)
	}
	// An id format nothing here anticipates still reaches the command, which
	// reads it itself.
	for _, id := range []string{"BDU:2024-00390", "RHSA-2025:1730", "PATCHSTACK/spectrum/wordpress-theme", "not an input"} {
		fresh := &cobra.Command{Use: "probe <vuln-id>", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
			got = args
			return nil
		}}
		wrapVulnCommand(fresh)
		fresh.SetArgs([]string{id})
		if err := fresh.Execute(); err != nil || got[0] != id {
			t.Fatalf("%s: got %v, %v", id, got, err)
		}
	}
}

// The capped fan-out runs the ids that matter first: CVE, GHSA and CNVD ids
// ahead of the other families, newest first.
func TestFanoutOrderRanksCVEGHSAAndCNVDNewestFirst(t *testing.T) {
	got := fanoutOrder([]string{"BDU:2022-01628", "CVE-2021-9999", "PYSEC-2022-1", "CVE-2022-22963", "GHSA-6v73-fgf6-w5j7", "CVE-2021-10001", "CNVD-2022-23944"})
	want := []string{"GHSA-6v73-fgf6-w5j7", "CVE-2022-22963", "CVE-2021-10001", "CVE-2021-9999", "CNVD-2022-23944", "PYSEC-2022-1", "BDU:2022-01628"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("fanoutOrder = %v\nwant %v", got, want)
	}
}

func TestInapplicableAnswersAreTheNothingHereKind(t *testing.T) {
	for msg, want := range map[string]bool{
		"snort-rules get: API error (400): Invalid vulnerability identifier. Traffic filter rules support CVE, GHSA, and CNVD identifiers only.": true,
		"failed to get timeline: API error (404): Vulnerability not found":                                                                       true,
		"CVE CVE-2022-22963 is not in the Vulnetix KEV catalogue":                                                                                true,
		"API error (500): boom":         false,
		"API error (401): unauthorized": false,
	} {
		if got := inapplicable(errors.New(msg)); got != want {
			t.Errorf("inapplicable(%q) = %v, want %v", msg, got, want)
		}
	}
}

// A purl names advisories in several families. An id the command cannot read
// (a BDU id on a CVE-only route) is skipped, not reported as a failure; a real
// failure still fails the command.
func TestFanoutSkipsIdsTheCommandCannotRead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/auth/token"):
			_, _ = w.Write([]byte(`{"token":"test-token"}`))
		case strings.HasSuffix(r.URL.Path, "/inputs/resolve"):
			_, _ = w.Write([]byte(`{"resolved":{"kinds":["purl"],"vulnIds":["BDU:2022-01628","CVE-2022-22963","cisco-sa-x"]}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("VULNETIX_API_KEY", "")
	oldURL, oldOrg, oldKey, oldCache, oldComm, oldCreds := vdbBaseURL, vdbOrgID, vdbSecretKey, vdbNoCache, vdbNoCommunity, vdbCreds
	t.Cleanup(func() {
		vdbBaseURL, vdbOrgID, vdbSecretKey, vdbNoCache, vdbNoCommunity, vdbCreds = oldURL, oldOrg, oldKey, oldCache, oldComm, oldCreds
	})
	vdbBaseURL, vdbOrgID, vdbSecretKey, vdbNoCache, vdbNoCommunity, vdbCreds = srv.URL, "00000000-0000-0000-0000-000000000000", "test", true, true, nil

	run := func(fail map[string]error) ([]string, error) {
		var ran []string
		c := &cobra.Command{Use: "probe <vuln-id>", Args: cobra.ExactArgs(1), RunE: func(_ *cobra.Command, args []string) error {
			ran = append(ran, args[0])
			return fail[args[0]]
		}}
		wrapVulnCommand(c)
		c.SetErr(io.Discard)
		c.SetArgs([]string{"pkg:maven/org.springframework.cloud/spring-cloud-function-core@3.1.6"})
		return ran, c.Execute()
	}

	ran, err := run(map[string]error{
		"BDU:2022-01628": errors.New("API error (400): Invalid vulnerability identifier. Traffic filter rules support CVE, GHSA, and CNVD identifiers only."),
		"cisco-sa-x":     errors.New("failed to get timeline: API error (404): Vulnerability not found"),
	})
	if err != nil {
		t.Fatalf("inapplicable ids failed the command: %v", err)
	}
	if strings.Join(ran, " ") != "CVE-2022-22963 cisco-sa-x BDU:2022-01628" {
		t.Errorf("ran %v, want the CVE first", ran)
	}

	if _, err := run(map[string]error{"CVE-2022-22963": errors.New("API error (500): boom")}); err == nil || !strings.Contains(err.Error(), "1 of 3 failed") {
		t.Errorf("a real failure must fail the command, got %v", err)
	}
}
