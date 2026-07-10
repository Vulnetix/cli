package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// The manifest is the machine-readable contract between this CLI and every
// place that documents it. Documentation sites check their snippets against
// docs/command-manifest.json so a renamed flag breaks a test rather than a
// user's pipeline.
//
// Regenerate with `just gen-command-manifest`.

// CommandManifest is the serialized shape of the Cobra tree.
type CommandManifest struct {
	Commands map[string]ManifestCommand `json:"commands"`
}

// ManifestCommand describes one command path (e.g. "auth login").
type ManifestCommand struct {
	Short      string   `json:"short"`
	Flags      []string `json:"flags"`
	Deprecated []string `json:"deprecatedFlags,omitempty"`
	Subs       []string `json:"subcommands,omitempty"`
}

var manifestCmd = &cobra.Command{
	Use:    "__manifest",
	Short:  "Emit the command tree as JSON (internal; used to validate documentation)",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		data, err := json.MarshalIndent(BuildCommandManifest(), "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, string(data))
		return nil
	},
}

// BuildCommandManifest walks the live root command and records every command
// path with its flags. Persistent flags are attributed to the command that
// declares them and to every descendant, because that is how a user sees them.
func BuildCommandManifest() CommandManifest {
	// Cobra registers --help and --version lazily during Execute, so a walk
	// done before then would omit them from the manifest.
	rootCmd.InitDefaultHelpFlag()
	rootCmd.InitDefaultVersionFlag()

	m := CommandManifest{Commands: map[string]ManifestCommand{}}
	walkCommand(rootCmd, nil, &m)
	return m
}

func walkCommand(c *cobra.Command, path []string, m *CommandManifest) {
	if c.Hidden || c.Name() == "help" || c.Name() == "completion" {
		return
	}

	name := strings.Join(path, " ")
	if name == "" {
		name = "vulnetix"
	}

	entry := ManifestCommand{Short: c.Short}

	seen := map[string]bool{}
	add := func(f *pflag.Flag) {
		if seen[f.Name] {
			return
		}
		seen[f.Name] = true
		if f.Deprecated != "" {
			entry.Deprecated = append(entry.Deprecated, f.Name)
			return
		}
		entry.Flags = append(entry.Flags, f.Name)
	}

	c.LocalFlags().VisitAll(func(f *pflag.Flag) { add(f) })
	c.InheritedFlags().VisitAll(func(f *pflag.Flag) { add(f) })

	for _, sub := range c.Commands() {
		if sub.Hidden || sub.Name() == "help" {
			continue
		}
		entry.Subs = append(entry.Subs, sub.Name())
	}

	sort.Strings(entry.Flags)
	sort.Strings(entry.Deprecated)
	sort.Strings(entry.Subs)
	m.Commands[name] = entry

	for _, sub := range c.Commands() {
		walkCommand(sub, append(append([]string{}, path...), sub.Name()), m)
	}
}

func init() {
	rootCmd.AddCommand(manifestCmd)
}
