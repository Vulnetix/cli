package cmd

import (
	"testing"
)

func resetFixFlags(t *testing.T) {
	t.Helper()
	for flag, value := range map[string]string{
		"strategy":                   "stable",
		"manifest":                   "",
		"max-major-bump":             "0",
		"sca-autofix":                "false",
		"sca-autofix-strategy":       "stable",
		"sca-autofix-manifest":       "",
		"sca-autofix-max-major-bump": "0",
		"path":                       ".",
	} {
		if err := fixCmd.Flags().Set(flag, value); err != nil {
			t.Fatalf("resetting fix --%s: %v", flag, err)
		}
	}
}

// TestApplyFixFlagAliasesMapsOntoEngineFlags pins the delegation: `fix` presents
// remediation-friendly names and hands the engine the --sca-autofix-* values it
// reads, with autofix forced on.
func TestApplyFixFlagAliasesMapsOntoEngineFlags(t *testing.T) {
	resetFixFlags(t)
	t.Cleanup(func() { resetFixFlags(t) })

	for flag, value := range map[string]string{
		"strategy":       "safest",
		"manifest":       "package.json",
		"max-major-bump": "2",
	} {
		if err := fixCmd.Flags().Set(flag, value); err != nil {
			t.Fatalf("setting --%s: %v", flag, err)
		}
	}

	if err := applyFixFlagAliases(fixCmd); err != nil {
		t.Fatalf("applyFixFlagAliases: %v", err)
	}

	assertFlag := func(name, want string) {
		t.Helper()
		got := fixCmd.Flags().Lookup(name)
		if got == nil {
			t.Fatalf("engine flag --%s is not registered on fix", name)
		}
		if got.Value.String() != want {
			t.Errorf("--%s = %q, want %q", name, got.Value.String(), want)
		}
	}
	assertFlag("sca-autofix-strategy", "safest")
	assertFlag("sca-autofix-manifest", "package.json")
	assertFlag("sca-autofix-max-major-bump", "2")
	assertFlag("sca-autofix", "true")
}

// TestApplyFixFlagAliasesForcesAutofixWithoutOverridingDefaults checks that an
// untouched alias does not clobber the engine default.
func TestApplyFixFlagAliasesForcesAutofixWithoutOverridingDefaults(t *testing.T) {
	resetFixFlags(t)
	t.Cleanup(func() { resetFixFlags(t) })

	if err := applyFixFlagAliases(fixCmd); err != nil {
		t.Fatalf("applyFixFlagAliases: %v", err)
	}
	if got := fixCmd.Flags().Lookup("sca-autofix").Value.String(); got != "true" {
		t.Errorf("sca-autofix = %q, want true", got)
	}
	if got := fixCmd.Flags().Lookup("sca-autofix-strategy").Value.String(); got != "stable" {
		t.Errorf("sca-autofix-strategy = %q, want the stable default", got)
	}
}

// TestFixCommandSurface documents what `fix` owns: the remediation knobs, the
// gates a remediation run can still enforce, and none of the scanner-family flags
// that have nothing to do with fixing dependencies.
func TestFixCommandSurface(t *testing.T) {
	target, _, err := rootCmd.Find([]string{"fix"})
	if err != nil {
		t.Fatalf("finding fix: %v", err)
	}
	if target.Name() != "fix" {
		t.Fatalf("resolved %q, want fix", target.Name())
	}
	// The autofix alias keeps the older mental model working.
	aliased, _, err := rootCmd.Find([]string{"autofix"})
	if err != nil || aliased.Name() != "fix" {
		t.Fatalf("autofix alias does not resolve to fix: %v", err)
	}

	for _, flag := range []string{"strategy", "manifest", "max-major-bump", "yes", "dry-run", "severity"} {
		if target.Flags().Lookup(flag) == nil {
			t.Errorf("fix is missing --%s", flag)
		}
	}
	// Present for the engine, hidden from help so there is one name per knob.
	for _, flag := range []string{"sca-autofix", "sca-autofix-strategy", "allow", "license-mode", "git-history"} {
		f := target.Flags().Lookup(flag)
		if f == nil {
			t.Errorf("fix should still register --%s for the engine", flag)
			continue
		}
		if !f.Hidden {
			t.Errorf("--%s should be hidden on fix", flag)
		}
	}
	// Rego rules have no autofix path, so the SAST flags must not appear.
	for _, flag := range []string{"rule", "list-default-rules", "disable-default-rules", "snippet-context"} {
		if target.Flags().Lookup(flag) != nil {
			t.Errorf("fix should not carry the SAST flag --%s", flag)
		}
	}
}
