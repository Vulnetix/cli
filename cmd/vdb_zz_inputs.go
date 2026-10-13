package cmd

// Every vulnerability-keyed vdb command takes every input kind.
//
// A command written for one vulnerability id (`vdb workarounds <vuln-id>`,
// `vdb exploits [vuln-id]`, `vdb kev get <CVE-ID>`, …) also takes, in that
// argument's place or through the input flags, a purl, a CPE, a TEI, a SWID tag,
// a package with --ecosystem and --package-version, a --vendor and --product, or
// a --cel expression. The input is resolved to vulnerability ids
// (GET /v2/inputs/resolve) and the command runs once for each, unchanged: a
// vulnerability id still goes straight to the command.
//
// This is done here, once, by wrapping the commands rather than in each of
// them, so a new vulnerability-keyed command gets it by naming its argument
// <vuln-id> or <CVE-ID>. The wrapping runs in an init function in a file whose
// name sorts after every vdb command file: Go runs a package's init functions
// in file-name order, and the commands must exist before they are wrapped
// (TestEveryVulnCommandTakesInputKinds holds this in place).

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// maxInputFanout caps how many vulnerabilities one input runs a command for.
const maxInputFanout = 25

// vulnArgUse matches a command whose first argument is a vulnerability id.
var vulnArgUse = regexp.MustCompile(`[<\[](CVE-ID|vuln-id)[>\]]`)

func init() { wrapVulnCommands(vdbCmd) }

// wrapVulnCommands wraps every vulnerability-keyed command under parent.
func wrapVulnCommands(parent *cobra.Command) {
	for _, c := range parent.Commands() {
		wrapVulnCommands(c)
		if vulnArgUse.MatchString(c.Use) && c.RunE != nil {
			wrapVulnCommand(c)
			wrappedVulnCommands = append(wrappedVulnCommands, c.CommandPath())
		}
	}
}

// wrappedVulnCommands records what was wrapped, for the test that guards it.
var wrappedVulnCommands []string

func wrapVulnCommand(c *cobra.Command) {
	f := &inputFlags{}
	added := addMissingInputFlags(c.Flags(), f)
	orig, origArgs := c.RunE, c.Args

	// Accept no argument when an input flag names the target.
	c.Args = func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 && anyFlagChanged(cmd, added) {
			return nil
		}
		if origArgs != nil {
			return origArgs(cmd, args)
		}
		return nil
	}

	c.RunE = func(cmd *cobra.Command, args []string) error {
		flagged, err := f.inputs(cmd.InOrStdin())
		if err != nil {
			return err
		}
		in := flagged
		rest := args
		if len(args) > 0 {
			fromArg, err := detectInput(args[0])
			isID := err == nil && len(fromArg.Kinds()) == 1 && len(fromArg.VulnIDs) == 1
			if flagged.Empty() && (isID || err != nil) {
				// A vulnerability id, or something the command reads itself (an
				// id format no pattern here anticipates): the command as it always was.
				return orig(cmd, args)
			}
			if err != nil {
				return err
			}
			in, rest = mergeInputs(fromArg, flagged), args[1:]
		}
		if in.Empty() {
			return orig(cmd, args)
		}
		if len(in.Kinds()) == 1 && len(in.VulnIDs) == 1 {
			return orig(cmd, append([]string{in.VulnIDs[0]}, rest...))
		}

		client := newVDBClient()
		client.APIVersion = "/v2"
		res, err := client.V2ResolveInputs(in)
		if err != nil {
			return fmt.Errorf("resolve %s: %w", in.Label(), err)
		}
		ids := fanoutOrder(res.VulnIDs)
		if len(ids) == 0 {
			fmt.Fprintf(cmd.ErrOrStderr(), "%s resolves to no known vulnerability.\n", in.Label())
			return nil
		}
		if len(ids) > maxInputFanout {
			fmt.Fprintf(cmd.ErrOrStderr(), "%s resolves to %d vulnerability ids; running for the first %d (CVE, GHSA and CNVD first, newest first). Narrow it with --package-version or --vuln-id.\n",
				in.Label(), len(ids), maxInputFanout)
			ids = ids[:maxInputFanout]
		}
		var failed, skipped []string
		for i, id := range ids {
			if len(ids) > 1 {
				fmt.Fprintf(cmd.ErrOrStderr(), "\n── %s (%d of %d, from %s)\n", id, i+1, len(ids), in.Label())
			}
			if err := orig(cmd, append([]string{id}, rest...)); err != nil {
				if len(ids) > 1 && inapplicable(err) {
					skipped = append(skipped, id)
					continue
				}
				failed = append(failed, id+": "+err.Error())
			}
		}
		if len(skipped) > 0 {
			fmt.Fprintf(cmd.ErrOrStderr(), "\nSkipped %d of %d ids this command does not read or has no record of: %s\n",
				len(skipped), len(ids), strings.Join(skipped, ", "))
		}
		if len(failed) > 0 {
			return fmt.Errorf("%d of %d failed:\n  %s", len(failed), len(ids), strings.Join(failed, "\n  "))
		}
		return nil
	}
}

// inapplicableAnswer matches an answer that says the id is not one the command
// reads (the traffic-filter and detection-rule routes take only CVE, GHSA and
// CNVD ids) or that it has no record of the id.
var inapplicableAnswer = regexp.MustCompile(`(?i)invalid vulnerability identifier|API error \(404\)|not found|is not in the vulnetix kev catalogue`)

// inapplicable reports whether a command's error for one of several ids from an
// input means "nothing here for this id" rather than a failure. One input names
// many advisories across many families, and an id the command cannot use is
// skipped, as the server does in its own fan-out.
func inapplicable(err error) bool { return inapplicableAnswer.MatchString(err.Error()) }

// fanoutOrder ranks the ids an input resolves to, so the capped run covers the
// ones that matter: CVE, GHSA and CNVD ids first, then the other families. The
// server already ranks /v2/inputs/resolve (known exploited first, then newest),
// and it alone knows which are exploited, so its order stands within a family.
// A server that sent them unranked (alphabetical) gets newest first instead.
func fanoutOrder(ids []string) []string {
	out := append([]string{}, ids...)
	rank := func(id string) int {
		u := strings.ToUpper(id)
		if strings.HasPrefix(u, "CVE-") || strings.HasPrefix(u, "GHSA-") || strings.HasPrefix(u, "CNVD-") {
			return 0
		}
		return 1
	}
	ranked := !sort.StringsAreSorted(ids)
	sort.SliceStable(out, func(i, j int) bool {
		if ri, rj := rank(out[i]), rank(out[j]); ri != rj {
			return ri < rj
		}
		return !ranked && naturalGreater(out[i], out[j])
	})
	return out
}

// naturalGreater compares ids by their dash-separated parts, numerically where
// both parts are numbers, so CVE-2024-10001 sorts above CVE-2024-9999.
func naturalGreater(a, b string) bool {
	pa, pb := strings.Split(a, "-"), strings.Split(b, "-")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		if pa[i] == pb[i] {
			continue
		}
		na, ea := strconv.Atoi(pa[i])
		nb, eb := strconv.Atoi(pb[i])
		if ea == nil && eb == nil {
			return na > nb
		}
		return pa[i] > pb[i]
	}
	return len(pa) > len(pb)
}

// addMissingInputFlags registers the input flags a command does not already
// define, and returns the names it added. A command's own flag of the same name
// (fixes --purl, remediation --vendor) keeps its meaning.
func addMissingInputFlags(fs *pflag.FlagSet, f *inputFlags) []string {
	all := pflag.NewFlagSet("inputs", pflag.ContinueOnError)
	addInputFlags(all, f)
	var added []string
	all.VisitAll(func(fl *pflag.Flag) {
		if fs.Lookup(fl.Name) == nil {
			fs.AddFlag(fl)
			added = append(added, fl.Name)
		}
	})
	return added
}

func anyFlagChanged(cmd *cobra.Command, names []string) bool {
	for _, n := range names {
		if fl := cmd.Flags().Lookup(n); fl != nil && fl.Changed {
			return true
		}
	}
	return false
}
