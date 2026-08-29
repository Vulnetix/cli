package cmd

import (
	"reflect"
	"testing"

	"github.com/spf13/pflag"
	"github.com/vulnetix/cli/v3/internal/pipeline"
)

// The scan family's analysis inputs travel as a single pipeline.Options rather
// than 40 positional parameters. That change removed a class of bug —
// `true, noSCA, true, true, true` was a real call site — but it introduces a
// different one: a flag can be registered, parsed, and then quietly not carried
// into Options, which looks exactly like the flag working.
//
// That is not hypothetical. --concurrency was read from the flag and threaded
// through every positional parameter without ever being used; only converting
// to a struct surfaced it, because Go reports an unused local but not an unused
// parameter.
//
// These tests pin the mapping so the next dropped flag fails here.

// flagToOption maps a scan-family flag to the Options field that must carry it.
// A flag deliberately not carried into Options is listed in notAnalysisInput
// below, with the reason.
var flagToOption = map[string]string{
	"path":                    "RootPath",
	"depth":                   "Depth",
	"exclude":                 "Excludes",
	"no-progress":             "NoProgress",
	"show-introduced-paths":   "ShowPaths",
	"no-exploits":             "NoExploits",
	"no-remediation":          "NoRemediation",
	"severity":                "SeverityThreshold",
	"exploits":                "ExploitThreshold",
	"block-malware":           "BlockMalware",
	"block-eol":               "BlockEOL",
	"block-unpinned":          "BlockUnpinned",
	"version-lag":             "VersionLag",
	"cooldown":                "CooldownDays",
	"jail":                    "Jail",
	"results-only":            "ResultsOnly",
	"dry-run":                 "DryRun",
	"ignore":                  "IgnoreGlobs",
	"ignore-git":              "IgnoreGit",
	"ignore-binaries":         "IgnoreBinaries",
	"git-history":             "GitHistory",
	"git-history-max-commits": "GitHistoryMaxCommits",
	"git-history-max-files":   "GitHistoryMaxFiles",
	"sca-autofix":             "SCAAutofix",
	"disable-default-rules":   "DisableDefaultRules",
	"rule":                    "RuleRefs",
	"rule-registry":           "RuleRegistry",
	"rule-id":                 "RuleID",
	"snippet-context":         "SnippetContext",
	"reachability":            "Reachability",
	// Deployment labels. All five land on the one Deployment field, because
	// they describe a single thing — where these results are deployed and who
	// owns them — and are consumed together.
	"project":     "Deployment",
	"cluster":     "Deployment",
	"namespace":   "Deployment",
	"environment": "Deployment",
	"tag":         "Deployment",
	// Third-party VEX. --no-vex is resolved into VEXFiles by scanopts rather
	// than carried separately, so the engine checks one thing instead of two.
	"vex-file": "VEXFiles",
	"no-vex":   "VEXFiles",
}

// notAnalysisInput are scan-family flags that legitimately never reach Options,
// each with the reason it does not.
var notAnalysisInput = map[string]string{
	"concurrency":                "retired: deprecated no-op, superseded by VULNETIX_SCA_CONCURRENCY",
	"output":                     "output routing is presentation; it stays in outputConfig",
	"format":                     "deprecated alias for --output",
	"paths":                      "deprecated alias for --show-introduced-paths",
	"include-ignored":            "consumed to compute RespectGitignore",
	"sast-include-ignored":       "consumed to compute RespectGitignore",
	"secrets-include-ignored":    "consumed to compute RespectGitignore",
	"iac-include-ignored":        "consumed to compute RespectGitignore",
	"containers-include-ignored": "consumed to compute RespectGitignore",
	"allow":                      "folded into Options.License",
	"allow-file":                 "folded into Options.License",
	"license-mode":               "folded into Options.License",
	"policy-file":                "folded into Options.License",
	"exceptions-file":            "folded into Options.License",
	"sca-autofix-strategy":       "folded into Options.SCAAutofixOpts",
	"sca-autofix-manifest":       "folded into Options.SCAAutofixOpts",
	"sca-autofix-max-major-bump": "folded into Options.SCAAutofixOpts",
	"yes":                        "folded into Options.SCAAutofixOpts",
	"block-eol-severity":         "sets the package-level eolBlockSeverity",
	"list-default-rules":         "a listing, handled before any scan runs",
	"suppress-test-code":         "sets the package-level suppressTestCode",
	"no-ci-package-analysis":     "consumed by manifest detection before the scan",
	"no-shell-package-analysis":  "consumed by manifest detection before the scan",
	"no-malscan":                 "malscan runs as its own pass outside runLocalScan",
	"show-detected":              "detection-time reporting",
	"show-all-manifests":         "detection-time reporting",
	"from-memory":                "deprecated; delegates to `report`",
	"fresh-exploits":             "deprecated; delegates to `report`",
	"fresh-advisories":           "deprecated; delegates to `report`",
	"fresh-vulns":                "deprecated; delegates to `report`",
	"container-rootfs":           "containers-only, consumed before the scan",
	"container-archive":          "containers-only, consumed before the scan",
	"no-binary-package-analysis": "containers-only, consumed before the scan",
	"include-home":               "malscan-only",
	"evaluate-sast":              "feature toggle, folded into the No* booleans",
	"evaluate-sca":               "feature toggle, folded into the No* booleans",
	"evaluate-licenses":          "feature toggle, folded into the No* booleans",
	"evaluate-secrets":           "feature toggle, folded into the No* booleans",
	"evaluate-iac":               "feature toggle, folded into the No* booleans",
	"enable-containers":          "feature toggle, folded into the No* booleans",
	"no-sast":                    "feature toggle, folded into the No* booleans",
	"no-sca":                     "feature toggle, folded into the No* booleans",
	"no-licenses":                "feature toggle, folded into the No* booleans",
	"no-secrets":                 "feature toggle, folded into the No* booleans",
	"no-containers":              "feature toggle, folded into the No* booleans",
	"no-iac":                     "feature toggle, folded into the No* booleans",
	"no-aibom":                   "AIBOM runs as its own pass outside runLocalScan",
	"no-cbom":                    "CBOM runs as its own pass outside runLocalScan",
}

func optionsFieldNames(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	typ := reflect.TypeOf(pipeline.Options{})
	for i := range typ.NumField() {
		out[typ.Field(i).Name] = true
	}
	return out
}

// TestFlagToOptionFieldsExist catches a rename on the Options side: the map
// above is only useful if every field it names is real.
func TestFlagToOptionFieldsExist(t *testing.T) {
	fields := optionsFieldNames(t)
	for flag, field := range flagToOption {
		if !fields[field] {
			t.Errorf("--%s maps to pipeline.Options.%s, which does not exist", flag, field)
		}
	}
}

// globalFlags are the root persistent flags every command inherits. They are
// process-wide concerns (identity, verbosity, telemetry), not analysis inputs.
//
// They are computed rather than listed because cobra only merges inherited
// flags into a command's flag set once the tree has been executed, so this test
// sees a different flag set depending on whether it runs alone or after another
// test in the package.
func globalFlags(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{"help": true}
	rootCmd.PersistentFlags().VisitAll(func(f *pflag.Flag) { out[f.Name] = true })
	return out
}

// TestEveryScanFlagIsAccountedFor catches the other direction: a new flag added
// to the scan family that nobody carried into Options. It must be either mapped
// or explicitly excused, so "I forgot" cannot pass silently.
func TestEveryScanFlagIsAccountedFor(t *testing.T) {
	global := globalFlags(t)
	for _, name := range scanFamily {
		cmd, _, err := rootCmd.Find([]string{name})
		if err != nil {
			t.Fatalf("finding %s: %v", name, err)
		}
		t.Run(name, func(t *testing.T) {
			cmd.Flags().VisitAll(func(f *pflag.Flag) {
				if _, mapped := flagToOption[f.Name]; mapped {
					return
				}
				if _, excused := notAnalysisInput[f.Name]; excused {
					return
				}
				if global[f.Name] {
					return
				}
				t.Errorf("--%s is registered on %s but is neither mapped to a "+
					"pipeline.Options field nor listed in notAnalysisInput. "+
					"Add it to one of them.", f.Name, name)
			})
		})
	}
}

// TestScanFamilyFlagSetIsNotEmpty guards the guard: if cobra ever stops
// reporting a command's own flags through Flags(), the test above would pass by
// inspecting nothing.
func TestScanFamilyFlagSetIsNotEmpty(t *testing.T) {
	global := globalFlags(t)
	for _, name := range scanFamily {
		cmd, _, err := rootCmd.Find([]string{name})
		if err != nil {
			t.Fatalf("finding %s: %v", name, err)
		}
		own := 0
		cmd.Flags().VisitAll(func(f *pflag.Flag) {
			if !global[f.Name] {
				own++
			}
		})
		if own < 20 {
			t.Errorf("%s reports only %d non-global flags; the ownership check is inspecting almost nothing", name, own)
		}
	}
}

// TestOptionsFieldsAreReachable is the inverse completeness check: every field
// on Options should be settable from somewhere, or it is dead weight that will
// drift out of sync with reality.
func TestOptionsFieldsAreReachable(t *testing.T) {
	mapped := map[string]bool{}
	for _, field := range flagToOption {
		mapped[field] = true
	}
	// Fields with no single flag behind them, each set from elsewhere.
	for _, field := range []string{
		"Files",            // manifest detection
		"NoSCA",            // feature booleans, from --evaluate-*/--no-*
		"NoSASTRules",      //
		"NoSecrets",        //
		"NoContainers",     //
		"NoIAC",            //
		"NoLicenses",       //
		"LockedKinds",      // specializedRuleKinds(cmd.Name())
		"RespectGitignore", // computed from the --*-include-ignored family
		"SCAAutofixOpts",   // built from the --sca-autofix-* family
		"AutofixResolved",  // set only by the confirmation re-scan
		"License",          // built from --allow/--allow-file/--license-mode
		"GitCtx",           // collected, not flagged
		"SysInfo",          //
		"SeedBOM",          //
		"VulnetixSeedBOM",  //
	} {
		mapped[field] = true
	}

	for field := range optionsFieldNames(t) {
		if !mapped[field] {
			t.Errorf("pipeline.Options.%s is set by nothing. Either wire it up or remove it.", field)
		}
	}
}

// TestConcurrencyIsRetiredNotRemoved pins how --concurrency was retired.
//
// It was advertised as "Max concurrent VDB queries" but nothing ever read it;
// SCA fan-out is governed by VULNETIX_SCA_CONCURRENCY (cmd/cli_sca.go). It
// survived because it was one of runLocalScan's 40 positional parameters, and
// Go does not report unused parameters.
//
// Deleting it outright would fail every pipeline that passes it with "unknown
// flag", so it is deprecated instead: still accepted, hidden from help, and it
// warns. Removal belongs in v4.
func TestConcurrencyIsRetiredNotRemoved(t *testing.T) {
	for _, name := range scanFamily {
		cmd, _, err := rootCmd.Find([]string{name})
		if err != nil {
			t.Fatalf("finding %s: %v", name, err)
		}
		f := cmd.Flags().Lookup("concurrency")
		if f == nil {
			t.Errorf("%s: --concurrency was removed outright; that breaks pipelines "+
				"that pass it. It must stay accepted-but-deprecated until v4.", name)
			continue
		}
		if f.Deprecated == "" {
			t.Errorf("%s: --concurrency must carry a deprecation message pointing at "+
				"VULNETIX_SCA_CONCURRENCY", name)
		}
		if !f.Hidden {
			t.Errorf("%s: a deprecated flag must not appear in help output", name)
		}
	}
}

// TestConcurrencyIsNotAnOptionsField guards the other half of the retirement:
// a field on the shared struct for a value nothing consumes is exactly how the
// gap survived in the first place.
func TestConcurrencyIsNotAnOptionsField(t *testing.T) {
	if optionsFieldNames(t)["Concurrency"] {
		t.Error("pipeline.Options.Concurrency is back. Nothing reads it; " +
			"VULNETIX_SCA_CONCURRENCY governs SCA fan-out.")
	}
}
