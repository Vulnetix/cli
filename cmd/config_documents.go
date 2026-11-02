package cmd

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/platformiac"
	configschemas "github.com/vulnetix/config-schemas"
)

// Config-as-code documents: the vulnetix.com/v1 kinds whose schemas live in
// github.com/vulnetix/config-schemas. This file holds the offline subcommands
// (validate, kinds, schema). They need no credentials and no network, so a
// pipeline can lint .vulnetix/config/ before anything is planned or applied.

// defaultConfigDir is where config documents live in a repository.
const defaultConfigDir = ".vulnetix/config"

// configDocument is one decoded document and the file it came from.
type configDocument struct {
	configschemas.Document
	Path  string
	Index int // 1-based position within its file
}

// discoverConfigDocuments reads documents through internal/platformiac, which
// owns the rule for what a Platform IaC document is: apiVersion vulnetix.com/v1
// and a known kind. With no -f it reads .vulnetix/config/** (skipping SARIF,
// CycloneDX and anything else that is not a document, with a note under -v)
// and, with wellKnown, .vulnetix/ai-firewall.yaml, license-policy.yaml and
// license-exceptions.yaml. A file named with -f must be a document. It
// returns the documents and how many files they came from.
func discoverConfigDocuments(cmd *cobra.Command, files []string, wellKnown bool) ([]configDocument, int, error) {
	var notes io.Writer
	if verboseLevel > 0 {
		notes = cmd.ErrOrStderr()
	}
	found, err := platformiac.Discover(platformiac.Options{
		Root: ".", Files: files, Stdin: cmd.InOrStdin(), IncludeWellKnown: wellKnown, Notes: notes,
	})
	if err != nil {
		return nil, 0, err
	}
	paths := map[string]bool{}
	docs := make([]configDocument, 0, len(found))
	for _, d := range found {
		paths[d.Path] = true
		docs = append(docs, configDocument{Document: d.Document, Path: d.Path, Index: d.Index})
	}
	return docs, len(paths), nil
}

// validateConfigDocuments checks every document against its kind's schema and
// that no kind and name appears twice, since a later duplicate would silently
// win at apply time. It returns one line per problem.
func validateConfigDocuments(docs []configDocument) ([]string, error) {
	v, err := platformiac.NewValidator()
	if err != nil {
		return nil, err
	}
	var problems []string
	seen := map[string]string{}
	for _, d := range docs {
		where := fmt.Sprintf("%s (document %d)", d.Path, d.Index)
		if err := v.Validate(d.Document); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %s", where, indentContinuation(err.Error())))
			continue
		}
		name := d.Name
		if name == "" {
			name = "default" // a singleton in its repository form
		}
		key := d.Kind + "/" + name
		if first, ok := seen[key]; ok {
			problems = append(problems, fmt.Sprintf("%s: %s %q is already defined in %s", where, d.Kind, d.Name, first))
			continue
		}
		seen[key] = where
	}
	return problems, nil
}

func indentContinuation(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), "\n", "\n    ")
}

func newConfigValidateCommand() *cobra.Command {
	var files []string
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Check config-as-code documents against their schemas, offline",
		Long: `Check vulnetix.com/v1 config documents against the schema of their kind.

A document is Platform IaC when its apiVersion is vulnetix.com/v1 and its kind is
one "vulnetix config kinds" lists. Reads .vulnetix/config/ (recursively) and the
well-known files .vulnetix/ai-firewall.yaml, license-policy.yaml and
license-exceptions.yaml, or the files and directories given with -f. "-f -"
reads standard input. A file may hold several documents separated by "---".

Other files in a folder (SARIF, CycloneDX, OpenVEX, memory) are skipped, with a
note under -v. A vulnetix.com/v1 document of an unknown kind, a file that mixes
documents with other content, a well-known file holding the wrong kind, and a
file named with -f that is not a document are errors.

Validation runs offline against the schemas built into this binary. It also
fails when two documents define the same kind and name. Exit status is 1 when
any document is invalid.`,
		Example: `  vulnetix config validate
  vulnetix config validate -f .vulnetix/config/quality-gate.yaml
  cat gate.yaml | vulnetix config validate -f -`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			docs, nfiles, err := discoverConfigDocuments(cmd, files, true)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if len(docs) == 0 {
				fmt.Fprintf(out, "no config documents (looked in %s and the well-known files)\n", defaultConfigDir)
				return nil
			}
			problems, err := validateConfigDocuments(docs)
			if err != nil {
				return err
			}
			for _, p := range problems {
				fmt.Fprintln(out, p)
			}
			if len(problems) > 0 {
				return fmt.Errorf("%d of %d documents invalid", len(problems), len(docs))
			}
			fmt.Fprintf(out, "%d documents valid in %d files\n", len(docs), nfiles)
			return nil
		},
	}
	cmd.Flags().StringArrayVarP(&files, "file", "f", nil, "file or directory of documents (repeatable; - for stdin)")
	return cmd
}

func newConfigKindsCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "kinds",
		Short: "List the config-as-code kinds this CLI understands",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			for _, k := range platformiac.Kinds() {
				fmt.Fprintln(cmd.OutOrStdout(), k)
			}
			return nil
		},
	}
}

func newConfigSchemaCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "schema <kind>",
		Short: "Print the JSON Schema of a config-as-code kind",
		Example: `  vulnetix config schema QualityGate
  vulnetix config schema QualityGate > QualityGate.schema.json`,
		Args: cobra.ExactArgs(1),
		ValidArgsFunction: func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
			return platformiac.Kinds(), cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if local, ok := platformiac.LocalKinds[args[0]]; ok {
				_, err := cmd.OutOrStdout().Write(local)
				return err
			}
			b, err := configschemas.Schema(args[0])
			if err != nil {
				return fmt.Errorf("%w; run 'vulnetix config kinds' for the list", err)
			}
			_, err = cmd.OutOrStdout().Write(b)
			return err
		},
	}
}

func init() {
	configCmd.AddCommand(newConfigValidateCommand())
	configCmd.AddCommand(newConfigKindsCommand())
	configCmd.AddCommand(newConfigSchemaCommand())
}
