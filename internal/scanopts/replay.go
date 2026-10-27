package scanopts

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// A suggested command (`vulnetix iac --explain <rule>`) has to find what it
// names, so it repeats the inputs of the run that printed it: the path, the
// exclusions, the registry, the VEX documents. Leave one out and the finding
// it points at is excluded, unscanned or never loaded, and the suggestion
// answers "nothing to explain".
//
// Inputs are replayed by default and the exceptions are listed, so a new input
// flag reaches every suggestion without anyone remembering to add it.
// TestEveryScanFlagDecidesWhetherExplainReplaysIt fails until a new flag is
// placed on one side or the other.

// NotReplayed lists the flags a suggested command does not repeat, with why.
var NotReplayed = map[string]string{
	// Supplied or replaced by the suggestion itself.
	"rule":          "the suggestion loads the pack that supplied its rule, not every pack",
	"rule-id":       "--explain narrows the run to the rule it names",
	"explain":       "the suggestion names its own query",
	"only":          "the suggestion names the scanner that owns the finding",
	"skip":          "the suggestion names the scanner that owns the finding",
	"evaluate-sast": "feature selection", "evaluate-sca": "feature selection",
	"evaluate-licenses": "feature selection", "evaluate-secrets": "feature selection",
	"evaluate-iac": "feature selection", "enable-containers": "feature selection",
	"no-sast": "feature selection", "no-sca": "feature selection", "no-licenses": "feature selection",
	"no-secrets": "feature selection", "no-containers": "feature selection", "no-iac": "feature selection",

	// The licence stage, which an explain run skips.
	"allow": "licence stage", "allow-file": "licence stage", "license-mode": "licence stage",
	"policy-file": "licence stage", "exceptions-file": "licence stage",

	// Labels on a written document; an explain run writes none.
	"bom-manufacturer": "document label", "lifecycle": "document label",
	"project": "document label", "cluster": "document label", "namespace": "document label",
	"environment": "document label", "tag": "document label",

	"concurrency": "how fast, not what is found",
	"no-cache":    "an explain run uses no result cache anyway",
	"no-banner":   "display",

	// What is shown, not what is found.
	"view": "display", "filter": "display", "min-severity": "display", "sort": "display",
	"show": "display", "hide": "display", "verbose": "display", "quiet": "display",
	"color": "display", "ascii": "display", "width": "display", "silent": "display",
	"no-progress": "display", "no-exploits": "display", "no-remediation": "display",
	"show-introduced-paths": "display", "paths": "display", "show-detected": "display",
	"show-all-manifests": "display", "results-only": "display", "no-analytics": "telemetry",

	// Where output goes.
	"output": "output destination", "format": "output destination",
	"output-file": "output destination", "snippet-context": "shapes SARIF output only",

	// Gates: an explain run never fails a gate.
	"fail-on": "gate", "severity": "gate", "block-malware": "gate", "block-eol": "gate",
	"block-eol-severity": "gate", "block-unpinned": "gate", "exploits": "gate",
	"version-lag": "gate", "cooldown": "gate", "jail": "gate",

	// Side effects and other modes: an explain run changes nothing.
	"dry-run": "mode", "list-default-rules": "mode", "from-memory": "mode",
	"fresh-exploits": "mode", "fresh-advisories": "mode", "fresh-vulns": "mode",
	"sca-autofix": "mode", "sca-autofix-strategy": "mode", "sca-autofix-manifest": "mode",
	"sca-autofix-max-major-bump": "mode", "yes": "mode",
	"disable-memory": "an explain run writes no memory anyway",
	"no-aibom":       "an explain run skips the AIBOM pass",
	"no-cbom":        "an explain run skips the CBOM pass",
	"no-malscan":     "an explain run skips the malscan pass",
	"no-upload":      "an explain run uploads nothing",
}

// ReplayArgs returns the flags the user set on cmd that a suggested command on
// target must repeat, in the order pflag visits them. A flag target does not
// register is dropped: `scan --rule-registry X` must not become an `sca`
// command that refuses to start.
func ReplayArgs(cmd, target *cobra.Command) []string {
	var out []string
	cmd.Flags().Visit(func(fl *pflag.Flag) {
		if _, skip := NotReplayed[fl.Name]; skip {
			return
		}
		if target == nil || (target.Flags().Lookup(fl.Name) == nil && target.InheritedFlags().Lookup(fl.Name) == nil) {
			return
		}
		out = append(out, flagWords(fl)...)
	})
	return out
}

// replayScanners are the commands a suggestion can name: the one that ran, and
// each scanner that owns a kind of finding.
var replayScanners = []string{"scan", "sca", "sast", "secrets", "iac", "containers"}

// replayFor computes ReplayArgs for every command a suggestion from cmd can
// name, keyed by that command's name.
func replayFor(cmd *cobra.Command) map[string][]string {
	out := map[string][]string{}
	for _, name := range append([]string{cmd.Name()}, replayScanners...) {
		if _, done := out[name]; done {
			continue
		}
		target := cmd
		if name != cmd.Name() {
			t, _, err := cmd.Root().Find([]string{name})
			if err != nil || t == nil || t.Name() != name {
				continue
			}
			target = t
		}
		out[name] = ReplayArgs(cmd, target)
	}
	return out
}

func flagWords(fl *pflag.Flag) []string {
	name := "--" + fl.Name
	switch v := fl.Value.(type) {
	case pflag.SliceValue:
		var out []string
		for _, s := range v.GetSlice() {
			out = append(out, name, s)
		}
		return out
	}
	if fl.Value.Type() == "bool" {
		if fl.Value.String() == "true" {
			return []string{name}
		}
		return []string{name + "=false"}
	}
	return []string{name, fl.Value.String()}
}
