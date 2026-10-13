package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// scanHelpGroups arranges a scan-family command's flags by the question each one
// answers, in the order a person asks them. Flags registered but not named here
// fall into "MORE OPTIONS", so adding a flag never hides it from help.
var scanHelpGroups = []struct {
	title string
	names []string
}{
	{"WHAT TO SCAN", []string{"path", "only", "skip", "exclude", "depth", "include-ignored", "reachability", "dry-run"}},
	{"WHAT TO SHOW", []string{"view", "filter", "min-severity", "sort", "show", "hide", "verbose", "quiet", "explain"}},
	{"WHEN TO FAIL", []string{"fail-on", "strict", "accept-defended", "jail"}},
	{"WHAT TO WRITE", []string{"output", "color", "ascii", "width", "disable-memory"}},
	{"FIXING", []string{"sca-autofix", "sca-autofix-strategy", "sca-autofix-manifest", "sca-autofix-max-major-bump", "yes"}},
}

// groupedUsage is the UsageFunc for the scan family. It prints the usage line and
// the flags by group, then the inherited flags, then the pointer to the
// subcommands' own help.
func groupedUsage(cmd *cobra.Command) error {
	out := cmd.OutOrStderr()
	fmt.Fprintf(out, "Usage:\n  %s\n", cmd.UseLine())
	if cmd.HasAvailableSubCommands() {
		fmt.Fprintf(out, "  %s [command]\n", cmd.CommandPath())
	}
	if len(cmd.Aliases) > 0 {
		fmt.Fprintf(out, "\nAliases:\n  %s\n", cmd.NameAndAliases())
	}

	local := cmd.LocalFlags()
	inherited := cmd.InheritedFlags()
	placed := map[string]bool{}
	lookup := func(name string) *pflag.Flag {
		if f := local.Lookup(name); f != nil {
			return f
		}
		return inherited.Lookup(name)
	}

	for _, g := range scanHelpGroups {
		set := pflag.NewFlagSet(g.title, pflag.ContinueOnError)
		for _, n := range g.names {
			if f := lookup(n); f != nil && !f.Hidden {
				set.AddFlag(f)
				placed[n] = true
			}
		}
		if usage := strings.TrimRight(set.FlagUsagesWrapped(100), "\n"); usage != "" {
			fmt.Fprintf(out, "\n%s\n%s\n", g.title, usage)
		}
	}

	more := pflag.NewFlagSet("more", pflag.ContinueOnError)
	local.VisitAll(func(f *pflag.Flag) {
		if !placed[f.Name] && !f.Hidden {
			more.AddFlag(f)
		}
	})
	if usage := strings.TrimRight(more.FlagUsagesWrapped(100), "\n"); usage != "" {
		fmt.Fprintf(out, "\nMORE OPTIONS\n%s\n", usage)
	}

	global := pflag.NewFlagSet("global", pflag.ContinueOnError)
	inherited.VisitAll(func(f *pflag.Flag) {
		if !placed[f.Name] && !f.Hidden {
			global.AddFlag(f)
		}
	})
	if usage := strings.TrimRight(global.FlagUsagesWrapped(100), "\n"); usage != "" {
		fmt.Fprintf(out, "\nGLOBAL OPTIONS\n%s\n", usage)
	}
	if cmd.HasAvailableSubCommands() {
		fmt.Fprintf(out, "\nUse \"%s [command] --help\" for more information about a command.\n", cmd.CommandPath())
	}
	return nil
}
