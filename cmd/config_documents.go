package cmd

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
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

// configDocumentFiles expands -f arguments into YAML/JSON files. A directory is
// walked recursively; "-" is standard input. With no arguments the default
// directory is read, and its absence is not an error: a repository with no
// config documents has nothing to validate.
func configDocumentFiles(args []string) ([]string, error) {
	if len(args) == 0 {
		if _, err := os.Stat(defaultConfigDir); errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		args = []string{defaultConfigDir}
	}
	var out []string
	for _, a := range args {
		if a == "-" {
			out = append(out, a)
			continue
		}
		st, err := os.Stat(a)
		if err != nil {
			return nil, err
		}
		if !st.IsDir() {
			out = append(out, a)
			continue
		}
		err = filepath.WalkDir(a, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			switch strings.ToLower(filepath.Ext(p)) {
			case ".yaml", ".yml", ".json":
				out = append(out, p)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(out)
	return out, nil
}

// readConfigDocuments decodes every document in the given files.
func readConfigDocuments(files []string, stdin io.Reader) ([]configDocument, error) {
	var docs []configDocument
	for _, p := range files {
		ds, err := decodeConfigFile(p, stdin)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		for i, d := range ds {
			docs = append(docs, configDocument{Document: d, Path: p, Index: i + 1})
		}
	}
	return docs, nil
}

// decodeConfigFile decodes one file, or standard input for "-".
func decodeConfigFile(p string, stdin io.Reader) ([]configschemas.Document, error) {
	if p == "-" {
		return configschemas.Decode(stdin)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return configschemas.Decode(f)
}

// validateConfigDocuments checks every document against its kind's schema and
// that no kind and name appears twice, since a later duplicate would silently
// win at apply time. It returns one line per problem.
func validateConfigDocuments(docs []configDocument) ([]string, error) {
	v, err := configschemas.NewValidator()
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
		key := d.Kind + "/" + d.Name
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

Reads every .yaml, .yml and .json file under .vulnetix/config/ (recursively), or
the files and directories given with -f. "-f -" reads standard input. A file
may hold several documents separated by "---".

Validation runs offline against the schemas built into this binary. It also
fails when two documents define the same kind and name. Exit status is 1 when
any document is invalid.`,
		Example: `  vulnetix config validate
  vulnetix config validate -f .vulnetix/config/quality-gate.yaml
  cat gate.yaml | vulnetix config validate -f -`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			paths, err := configDocumentFiles(files)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if len(paths) == 0 {
				fmt.Fprintf(out, "no config documents (looked in %s)\n", defaultConfigDir)
				return nil
			}
			docs, err := readConfigDocuments(paths, cmd.InOrStdin())
			if err != nil {
				return err
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
			fmt.Fprintf(out, "%d documents valid in %d files\n", len(docs), len(paths))
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
			for _, k := range configschemas.Kinds() {
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
			return configschemas.Kinds(), cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
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
