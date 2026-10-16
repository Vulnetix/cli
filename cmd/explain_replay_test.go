package cmd

import (
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/vulnetix/cli/v3/internal/scanopts"
)

// replayedForExplain lists the flags a suggested command repeats, with why. A
// flag is either here or in scanopts.NotReplayed; one in neither fails the test,
// so adding a flag means deciding whether a suggestion still finds its finding
// without it.
var replayedForExplain = map[string]string{
	"path":                       "the files scanned",
	"depth":                      "the files scanned",
	"exclude":                    "the files scanned",
	"ignore":                     "the files scanned",
	"include-ignored":            "the files scanned",
	"sast-include-ignored":       "the files scanned",
	"secrets-include-ignored":    "the files scanned",
	"iac-include-ignored":        "the files scanned",
	"containers-include-ignored": "the files scanned",
	"sca-include-ignored":        "the files scanned",
	"ignore-git":                 "the files scanned",
	"ignore-binaries":            "the files scanned",
	"git-history":                "the files scanned",
	"git-history-max-commits":    "the files scanned",
	"git-history-max-files":      "the files scanned",
	"rule-registry":              "where the pack is fetched from",
	"disable-default-rules":      "which rules can match",
	"suppress-test-code":         "which findings are kept",
	"no-ci-package-analysis":     "which packages are found",
	"no-shell-package-analysis":  "which packages are found",
	"vex-file":                   "which findings VEX settles",
	"no-vex":                     "which findings VEX settles",
	"strict":                     "how a verdict is counted",
	"accept-defended":            "how a verdict is counted",
	"reachability":               "the evidence explained",
	"org-id":                     "whose data is asked for",
	"container-archive":          "the image scanned",
	"container-rootfs":           "the image scanned",
	"no-binary-package-analysis": "which packages are found",
}

func TestEveryScanFlagDecidesWhetherExplainReplaysIt(t *testing.T) {
	seen := map[string]bool{}
	var unplaced []string
	for _, c := range []*cobra.Command{scanCmd, scaCmd, sastCmd, secretsCmd, iacCmd, containersCmd} {
		visit := func(fl *pflag.Flag) {
			if seen[fl.Name] {
				return
			}
			seen[fl.Name] = true
			_, replayed := replayedForExplain[fl.Name]
			_, skipped := scanopts.NotReplayed[fl.Name]
			switch {
			case replayed && skipped:
				t.Errorf("--%s is both replayed and not replayed", fl.Name)
			case !replayed && !skipped:
				unplaced = append(unplaced, fl.Name)
			}
		}
		c.Flags().VisitAll(visit)
		c.InheritedFlags().VisitAll(visit)
	}
	sort.Strings(unplaced)
	for _, n := range unplaced {
		t.Errorf("--%s: add it to replayedForExplain or scanopts.NotReplayed", n)
	}
}

func TestReplayArgsRepeatsInputsTheTargetTakes(t *testing.T) {
	src := &cobra.Command{Use: "scan"}
	src.Flags().String("path", "", "")
	src.Flags().StringArray("exclude", nil, "")
	src.Flags().String("rule-registry", "", "")
	src.Flags().StringArray("rule", nil, "")
	src.Flags().String("view", "", "")
	src.Flags().Bool("no-vex", false, "")
	if err := src.ParseFlags([]string{"--path", "infra", "--exclude", "testdata/**", "--exclude", "vendor",
		"--rule-registry", "https://git.example", "--rule", "a/b", "--view", "plain", "--no-vex"}); err != nil {
		t.Fatal(err)
	}
	sca := &cobra.Command{Use: "sca"}
	sca.Flags().String("path", "", "")
	sca.Flags().StringArray("exclude", nil, "")
	sca.Flags().Bool("no-vex", false, "")
	got := strings.Join(scanopts.ReplayArgs(src, sca), " ")
	want := "--exclude testdata/** --exclude vendor --no-vex --path infra"
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}
