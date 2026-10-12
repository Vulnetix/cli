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
		ids := res.VulnIDs
		if len(ids) == 0 {
			fmt.Fprintf(cmd.ErrOrStderr(), "%s resolves to no known vulnerability.\n", in.Label())
			return nil
		}
		if len(ids) > maxInputFanout {
			fmt.Fprintf(cmd.ErrOrStderr(), "%s resolves to %d vulnerability ids; running for the first %d. Narrow it with --package-version or --vuln-id.\n",
				in.Label(), len(ids), maxInputFanout)
			ids = ids[:maxInputFanout]
		}
		var failed []string
		for i, id := range ids {
			if len(ids) > 1 {
				fmt.Fprintf(cmd.ErrOrStderr(), "\n── %s (%d of %d, from %s)\n", id, i+1, len(ids), in.Label())
			}
			if err := orig(cmd, append([]string{id}, rest...)); err != nil {
				failed = append(failed, id+": "+err.Error())
			}
		}
		if len(failed) > 0 {
			return fmt.Errorf("%d of %d failed:\n  %s", len(failed), len(ids), strings.Join(failed, "\n  "))
		}
		return nil
	}
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
