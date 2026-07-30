package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/sast"
)

// handleSASTRuleListing serves --list-default-rules for whichever command was
// invoked. Every command that registers the flag (scan, sast, secrets,
// containers, iac — see addSASTFlags) routes through here: the flag used to be
// implemented in scanCmd.RunE only, so `vulnetix sast --list-default-rules` ran a
// full scan and printed nothing.
//
// Returns handled=true when the listing was printed and the caller should return
// without scanning.
func handleSASTRuleListing(cmd *cobra.Command) (handled bool, err error) {
	if cmd == nil || cmd.Flags().Lookup("list-default-rules") == nil {
		return false, nil
	}
	if list, _ := cmd.Flags().GetBool("list-default-rules"); !list {
		return false, nil
	}
	return true, listBuiltinSASTRules()
}

// listBuiltinSASTRules loads the default embedded rules, extracts metadata, and
// prints a table of built-in SAST rules.
func listBuiltinSASTRules() error {
	modules, err := sast.LoadAllModules(sast.DefaultRulesFS, false, nil, "", os.Stderr)
	if err != nil {
		return fmt.Errorf("load default rules: %w", err)
	}
	if len(modules) == 0 {
		fmt.Fprintln(os.Stdout, "No built-in SAST rules found.")
		return nil
	}

	eng := sast.NewEngine(modules, ".")
	rules, err := eng.ListRules()
	if err != nil {
		return fmt.Errorf("list rules: %w", err)
	}
	if len(rules) == 0 {
		fmt.Fprintln(os.Stdout, "No built-in SAST rules found.")
		return nil
	}

	t := display.NewTerminal()
	cols := []display.Column{
		{Header: "ID", MinWidth: 12, MaxWidth: 16},
		{Header: "Severity", MinWidth: 8, MaxWidth: 10, Color: func(s string) string {
			return display.SeverityText(t, strings.ToLower(s))
		}},
		{Header: "Languages", MinWidth: 10, MaxWidth: 20},
		{Header: "Name", MinWidth: 20, MaxWidth: 50},
	}
	rows := make([][]string, 0, len(rules))
	for _, r := range rules {
		rows = append(rows, []string{
			r.ID,
			r.Severity,
			strings.Join(r.Languages, ", "),
			r.Name,
		})
	}
	fmt.Fprintln(os.Stdout)
	fmt.Fprint(os.Stdout, display.Table(t, cols, rows))
	fmt.Fprintf(os.Stdout, "\n%d built-in rules\n", len(rules))
	return nil
}
