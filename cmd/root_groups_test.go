package cmd

import (
	"strings"
	"testing"
)

// The root help is grouped (Get started, Scan, VDB, Platform). A new
// top-level command has to be placed in commandGroups, or it is listed under
// "Additional Commands" with help and completion.
func TestEveryRootCommandHasAGroup(t *testing.T) {
	assignCommandGroups()
	ungrouped := map[string]bool{"help": true, "completion": true}
	for _, c := range rootCmd.Commands() {
		if c.Hidden || ungrouped[c.Name()] {
			continue
		}
		if c.GroupID == "" {
			t.Errorf("top-level command %q is in no help group; add it to commandGroups in cmd/root.go", c.Name())
		}
	}
}

func TestCommandGroupsNameRealCommands(t *testing.T) {
	assignCommandGroups()
	have := map[string]bool{}
	for _, c := range rootCmd.Commands() {
		have[c.Name()] = true
	}
	seen := map[string]string{}
	for _, g := range commandGroups {
		for _, name := range g.commands {
			if !have[name] {
				t.Errorf("commandGroups lists %q, which is not a top-level command", name)
			}
			if prev, ok := seen[name]; ok {
				t.Errorf("%q is in both %s and %s", name, prev, g.group.ID)
			}
			seen[name] = g.group.ID
		}
	}
}

func TestRootHelpShowsGroupsAndFirstSteps(t *testing.T) {
	assignCommandGroups()
	usage := rootCmd.UsageString()
	for _, want := range []string{"Get started:", "Scan:", "VDB:", "Platform:"} {
		if !strings.Contains(usage, want) {
			t.Errorf("root help has no %q section", want)
		}
	}
	for _, want := range []string{"vulnetix auth login", "vulnetix scan", "https://docs.vulnetix.com/cli/"} {
		if !strings.Contains(rootCmd.Long, want) {
			t.Errorf("root Long text does not mention %q", want)
		}
	}
}
