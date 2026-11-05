package cmd

import (
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// CommandPaths lists every runnable command, as words after `vulnetix`.
func CommandPaths() []string {
	var out []string
	var walk func(c *cobra.Command, prefix string)
	walk = func(c *cobra.Command, prefix string) {
		for _, s := range c.Commands() {
			if s.Name() == "help" {
				continue
			}
			name := strings.TrimSpace(prefix + " " + s.Name())
			if s.Runnable() {
				out = append(out, name)
			}
			walk(s, name)
		}
	}
	walk(rootCmd, "")
	sort.Strings(out)
	return out
}
