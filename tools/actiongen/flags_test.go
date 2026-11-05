package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/vulnetix/cli/v4/cmd"
)

// splitArgv separates a command's subcommand path from the flags in it.
func splitArgv(argv []string) (path, flags []string) {
	inFlags := false
	for _, a := range argv {
		if name, ok := strings.CutPrefix(a, "--"); ok {
			flags = append(flags, name)
			inFlags = true
		} else if !inFlags { // after a flag, a word is that flag's value
			path = append(path, a)
		}
	}
	return path, flags
}

func requireFlags(t *testing.T, who string, path, flags []string) {
	t.Helper()
	for _, f := range flags {
		ok, err := cmd.CommandAcceptsFlag(path, f)
		if err != nil {
			t.Errorf("%s: vulnetix %s: %v", who, strings.Join(path, " "), err)
			return
		}
		if !ok {
			t.Errorf("%s passes --%s to `vulnetix %s`, which does not accept it", who, f, strings.Join(path, " "))
		}
	}
}

// Every flag a generated action passes must exist on the command it runs. An
// action that fails with "unknown flag" only when a caller turns a feature on
// is the bug this guards: `sca` once failed this way with github-code-scanning.
func TestEveryFlagAnActionPassesIsAccepted(t *testing.T) {
	for _, a := range actions {
		if !generic(a) {
			continue
		}
		path, flags := splitArgv(a.Command)
		if len(a.FlagHost) > 0 {
			path = a.FlagHost
		}
		if a.Path {
			flags = append(flags, "path")
		}
		if a.Scan && (a.CodeScanning || a.DependencyGraph) {
			// run.sh passes --github-publish to a scan-family command.
			flags = append(flags, "github-publish", "github-publish-dry-run")
		}
		for _, in := range a.Inputs {
			f := strings.TrimPrefix(strings.TrimPrefix(in.Flag, "bool:"), "lines:")
			if name, ok := strings.CutPrefix(f, "--"); ok {
				flags = append(flags, name)
			}
		}
		requireFlags(t, "action "+a.Name, path, flags)
	}
}

// Every command is either run by an action or declined with a reason, so a new
// subcommand cannot ship without someone deciding how a workflow uses it.
func TestEverySubcommandDecided(t *testing.T) {
	covered := map[string]bool{}
	for _, a := range actions {
		if a.Setup {
			continue
		}
		path, _ := splitArgv(a.Command)
		if a.Script == "config" {
			path = displayCommand(a)
		}
		if a.Script == "publish" {
			continue
		}
		covered[strings.Join(path, " ")] = true
	}
	covered["config validate"] = true // config-plan with validate-only
	covered["vex"] = true             // the vex action takes the subcommand as an input
	covered["cdx"] = true             // sbom
	for _, c := range []string{"gha upload", "attest verify"} {
		covered[c] = true
	}
	decided := func(name string) bool {
		for {
			if covered[name] || declined[name] != "" {
				return true
			}
			i := strings.LastIndex(name, " ")
			if i < 0 {
				return false
			}
			name = name[:i]
		}
	}
	for _, name := range cmd.CommandPaths() {
		if !decided(name) {
			t.Errorf("`vulnetix %s` has neither an action nor a decision: add one in tools/actiongen/spec.go or decided.go", name)
		}
	}
	for name := range declined {
		found := false
		for _, c := range cmd.CommandPaths() {
			if c == name || strings.HasPrefix(c, name+" ") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("declined lists `%s`, which is not a command", name)
		}
	}
}

// The scan-family actions pass --github-publish through run.sh, which decides
// by commands.sh's vx_scan. The two lists must agree with the spec.
func TestScanActionsMatchCommandsSh(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "action-lib", "commands.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range actions {
		if a.Scan && !strings.Contains(string(raw), "vx_scan=true") {
			t.Errorf("%s is a scan action but commands.sh marks none", a.Name)
		}
	}
}

// publish.sh runs `vulnetix gha publish <target>` with flags of its own.
func TestPublishScriptFlagsAreAccepted(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "action-lib", "publish.sh"))
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile(`args=\((gha publish [a-z-]+)`)
	flag := regexp.MustCompile(`--([a-z][a-z-]*)`)
	var path []string
	seen := 0
	for _, line := range strings.Split(string(raw), "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "#") {
			continue
		}
		if m := block.FindStringSubmatch(line); m != nil {
			path = strings.Fields(m[1])
		}
		if path == nil {
			continue
		}
		for _, f := range flag.FindAllStringSubmatch(line, -1) {
			requireFlags(t, "publish.sh", path, []string{f[1]})
			seen++
		}
	}
	if seen == 0 {
		t.Fatal("found no flags in publish.sh; the test no longer reads it")
	}
}
