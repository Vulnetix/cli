package cmd

// Scan-time org quality-gate enforcement override.
//
// When a scan runs under a real (non-community) authenticated org, the org's
// stored quality-gate policy is fetched once and applied over the scan's
// control flags. The decided semantics are: ORG POLICY ALWAYS WINS — a set org
// value overrides even an explicitly-passed CLI flag. A setting the org left
// null leaves the caller's flag (or builtin default) untouched. Verbose output
// notes every supersede / application; non-authenticated scans use only the
// CLI flags (this function returns early).

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/scan"
	"github.com/vulnetix/cli/v3/pkg/auth"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// qualityGateOverridePointers bundles pointers to the nine scan-time control
// locals in runScanWithFeatures so applyOrgQualityGate can overwrite each in
// place when the org enforces a value. Field names mirror the camelCase config
// keys returned by /v2/cli.quality-gate-get.
type qualityGateOverridePointers struct {
	blockEol               *bool
	blockMalware           *bool
	blockUnpinned          *bool
	cooldown               *int
	versionLag             *int
	scaAutofixMaxMajorBump *int
	exploits               *string
	severity               *string
	scaAutofixStrategy     *string

	// eolBuckets is the org's EOL-horizon-to-severity mapping. Unlike the nine
	// fields above it is NOT nullable enforcement — the columns are NOT NULL and
	// carry defaults — so it is not an override but a setting, and it is only read
	// when --block-eol is in effect.
	eolBuckets *scan.EOLSeverityBuckets
}

// applyOrgQualityGate fetches the authenticated org's quality-gate policy and
// applies every set (non-null) enforcement value over the caller's scan flags.
// It is a no-op (caller/builtin values stand) when the scan is unauthenticated
// or community-tier, when credentials cannot be loaded, when the lookup fails,
// or when the org has no policy row. All diagnostic output is gated on the
// existing --verbose flag.
func applyOrgQualityGate(cmd *cobra.Command, p qualityGateOverridePointers) {
	creds, err := auth.LoadCredentials()
	if err != nil || creds == nil || auth.IsCommunity(creds) {
		if verbose {
			fmt.Fprintln(os.Stderr, "Org quality gate: skipped (no authenticated org — using scan flags only).")
		}
		return
	}

	client := vdb.NewClientFromCredentials(creds)
	client.APIVersion = "/v2"
	client.BaseURL = vdb.DefaultBaseURL
	if f := cmd.Flags().Lookup("base-url"); f != nil {
		if baseURL, _ := cmd.Flags().GetString("base-url"); baseURL != "" {
			client.BaseURL = baseURL
		}
	}

	resp, err := client.CliQualityGateGet(envForCli())
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "Org quality gate: lookup failed (%v) — using scan flags only.\n", err)
		}
		return
	}

	config, _ := resp.Data["config"].(map[string]any)
	if config == nil {
		if verbose {
			fmt.Fprintln(os.Stderr, "Org quality gate: no policy configured — using scan flags only.")
		}
		return
	}

	applied := 0

	applyBool := func(flag, key string, target *bool) {
		orgVal, ok := qgConfigBool(config, key)
		if !ok {
			return
		}
		callerVal := *target
		*target = orgVal
		applied++
		noteOverride(cmd, flag, fmt.Sprintf("%t", callerVal), fmt.Sprintf("%t", orgVal))
	}
	applyInt := func(flag, key string, target *int) {
		orgVal, ok := qgConfigInt(config, key)
		if !ok {
			return
		}
		callerVal := *target
		*target = orgVal
		applied++
		noteOverride(cmd, flag, fmt.Sprintf("%d", callerVal), fmt.Sprintf("%d", orgVal))
	}
	applyString := func(flag, key string, target *string) {
		orgVal, ok := qgConfigString(config, key)
		if !ok {
			return
		}
		callerVal := *target
		*target = orgVal
		applied++
		noteOverride(cmd, flag, callerVal, orgVal)
	}

	// The EOL severity buckets. These four columns have existed, with sensible
	// defaults, since the quality-gate table was created — and nothing has ever
	// read them, because until organisations were seeded a config row, this handler
	// returned {"config": null} for every org on the platform and we never got this
	// far. They grade an EOL horizon instead of treating every EOL alike.
	if p.eolBuckets != nil {
		if v, ok := qgConfigString(config, "eolRetiredSeverity"); ok {
			p.eolBuckets.Retired = v
		}
		if v, ok := qgConfigString(config, "eolWithin30DaysSeverity"); ok {
			p.eolBuckets.Within30Days = v
		}
		if v, ok := qgConfigString(config, "eolThisQuarterSeverity"); ok {
			p.eolBuckets.ThisQuarter = v
		}
		if v, ok := qgConfigString(config, "eolNextQuarterSeverity"); ok {
			p.eolBuckets.NextQuarter = v
		}
	}

	applyBool("block-eol", "blockEol", p.blockEol)
	applyBool("block-malware", "blockMalware", p.blockMalware)
	applyBool("block-unpinned", "blockUnpinned", p.blockUnpinned)
	applyInt("cooldown", "cooldown", p.cooldown)
	applyInt("version-lag", "versionLag", p.versionLag)
	applyInt("sca-autofix-max-major-bump", "scaAutofixMaxMajorBump", p.scaAutofixMaxMajorBump)
	applyString("exploits", "exploits", p.exploits)
	applyString("severity", "severity", p.severity)
	applyString("sca-autofix-strategy", "scaAutofixStrategy", p.scaAutofixStrategy)

	if applied > 0 && verbose {
		fmt.Fprintf(os.Stderr, "Org quality gate: applied %s from org policy (org policy always wins).\n",
			pluralise("setting", applied))
	}
}

// noteOverride emits the verbose supersede/applied line for one enforcement
// field. When the caller explicitly set the flag and the org value differs, it
// notes the supersede; when the caller did not set it, it notes the org policy
// application. Output is gated on --verbose. callerVal/orgVal are already
// stringified by the caller.
func noteOverride(cmd *cobra.Command, flag, callerVal, orgVal string) {
	if !verbose {
		return
	}
	if cmd.Flags().Changed(flag) {
		if callerVal != orgVal {
			fmt.Fprintf(os.Stderr, "--%s %s superseded by org policy: %s\n", flag, callerVal, orgVal)
		}
		return
	}
	fmt.Fprintf(os.Stderr, "org policy applied: --%s %s\n", flag, orgVal)
}

// qgConfigBool / qgConfigInt / qgConfigString read one nullable enforcement
// field from the cli.quality-gate-get config map. The second return is false
// when the org left the field null (absent or JSON null), so the caller leaves
// its local untouched. JSON numbers decode as float64.
func qgConfigBool(m map[string]any, key string) (bool, bool) {
	v, ok := m[key].(bool)
	return v, ok
}

func qgConfigInt(m map[string]any, key string) (int, bool) {
	if v, ok := m[key].(float64); ok {
		return int(v), true
	}
	return 0, false
}

func qgConfigString(m map[string]any, key string) (string, bool) {
	if v, ok := m[key].(string); ok && v != "" {
		return v, true
	}
	return "", false
}
