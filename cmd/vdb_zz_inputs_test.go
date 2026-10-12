package cmd

import (
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
