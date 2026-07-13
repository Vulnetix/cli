package cmd

import (
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/pkg/auth"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

type packageFirewallRequestKind string

const (
	packageFirewallPolicyRequest packageFirewallRequestKind = "policy"
	packageFirewallMirrorRequest packageFirewallRequestKind = "mirror"
)

type builtPackageFirewallRequest struct {
	Kind   packageFirewallRequestKind
	Config vdb.CliPackageFirewallConfigRequest
	Mirror vdb.CliPackageFirewallMirrorRequest
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage Vulnetix configuration",
}

var configSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Set Vulnetix configuration",
}

// eolPolicySeverities is the validated lowercase severity enum for the
// org-wide EOL quality-gate policy. "skip" disables findings for a bucket.
var eolPolicySeverities = []string{"skip", "low", "medium", "high", "critical"}

func validateSeverity(flag, value string) error {
	for _, s := range eolPolicySeverities {
		if value == s {
			return nil
		}
	}
	return fmt.Errorf("--%s must be one of: %s", flag, strings.Join(eolPolicySeverities, ", "))
}

// Enforcement-policy enums for the org-wide quality gate. These mirror the
// scan-time --severity / --exploits / --sca-autofix-strategy flags exactly so
// the stored org value can override the caller's flag byte-for-byte.
var (
	qualityGateSeverities    = []string{"low", "medium", "high", "critical"}
	qualityGateExploits      = []string{"poc", "active", "weaponized"}
	qualityGateAutofixStrats = []string{"latest", "safest", "stable"}
)

func validateEnum(flag, value string, allowed []string) error {
	for _, a := range allowed {
		if value == a {
			return nil
		}
	}
	return fmt.Errorf("--%s must be one of: %s", flag, strings.Join(allowed, ", "))
}

func newConfigSetPackageFirewallCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "package-firewall [ecosystem] [url]",
		Short: "Set Package Firewall policy and mirrors",
		Long: `Set Vulnetix Package Firewall policy thresholds or ecosystem mirror records.

Mirror form:
  vulnetix config set package-firewall <ecosystem> <url> [--priority N] [--enable | --disable]

Policy form:
  vulnetix config set package-firewall --cvss-threshold 7 --block-malware --cooldown-days 3`,
		Args: cobra.RangeArgs(0, 2),
		RunE: runConfigSetPackageFirewall,
	}

	cmd.Flags().Float64("cvss-threshold", 0, "CVSS block threshold (0-10)")
	cmd.Flags().Float64("epss-threshold", 0, "EPSS block threshold (0-1)")
	cmd.Flags().Float64("cess-threshold", 0, "CESS block threshold (0-10)")
	cmd.Flags().Bool("block-malware", false, "Block malicious packages")
	cmd.Flags().Bool("block-eol", false, "Block end-of-life packages")
	cmd.Flags().Bool("block-kev", false, "Block CISA KEV vulnerabilities")
	cmd.Flags().Bool("block-weaponized-exploits", false, "Block weaponized exploits")
	cmd.Flags().Bool("block-active-exploits", false, "Block active exploits")
	cmd.Flags().Bool("block-poc-exploits", false, "Block proof-of-concept exploits")
	cmd.Flags().Bool("block-bad-actors", false, "Block bad-actor packages")
	cmd.Flags().Int("cooldown-days", 0, "Minimum package age in days")
	cmd.Flags().Int("version-lag", 0, "Required version lag before allowing packages")
	cmd.Flags().Int("priority", 0, "Mirror priority")
	cmd.Flags().Bool("enable", false, "Enable an existing or new mirror")
	cmd.Flags().Bool("disable", false, "Disable an existing or new mirror")
	cmd.Flags().String("base-url", vdb.DefaultBaseURL, "VDB API base URL")
	cmd.Flags().StringP("output", "o", "pretty", "Output format (pretty, json)")

	_ = cmd.RegisterFlagCompletionFunc("output", cobra.FixedCompletions([]string{"pretty", "json"}, cobra.ShellCompDirectiveNoFileComp))
	return cmd
}

func runConfigSetPackageFirewall(cmd *cobra.Command, args []string) error {
	output, _ := cmd.Flags().GetString("output")
	switch output {
	case "", "pretty":
		initDisplayContext(cmd, display.ModeText)
	case "json":
		initDisplayContext(cmd, display.ModeJSON)
	default:
		return fmt.Errorf("--output must be one of: pretty, json")
	}

	built, err := buildPackageFirewallRequest(cmd, args)
	if err != nil {
		return err
	}

	client, err := newPackageFirewallConfigClient(cmd)
	if err != nil {
		return err
	}

	ctx := display.FromCommand(cmd)
	env := envForCli()
	switch built.Kind {
	case packageFirewallMirrorRequest:
		resp, err := client.CliPackageFirewallMirror(env, built.Mirror)
		if err != nil {
			return err
		}
		if ctx.IsJSON() {
			return ctx.Logger.ResultJSON(resp.Data)
		}
		ctx.Logger.Result(renderPackageFirewallResult(ctx, "Package Firewall mirror updated", resp.Data))
	case packageFirewallPolicyRequest:
		resp, err := client.CliPackageFirewallConfig(env, built.Config)
		if err != nil {
			return err
		}
		if ctx.IsJSON() {
			return ctx.Logger.ResultJSON(resp.Data)
		}
		ctx.Logger.Result(renderPackageFirewallResult(ctx, "Package Firewall policy updated", resp.Data))
	default:
		return fmt.Errorf("unknown package-firewall request kind %q", built.Kind)
	}
	return nil
}

func newPackageFirewallConfigClient(cmd *cobra.Command) (*vdb.Client, error) {
	creds, err := auth.LoadCredentials()
	if err != nil {
		return nil, fmt.Errorf("authentication required: %w\nRun 'vulnetix auth login' to authenticate", err)
	}
	client := vdb.NewClientFromCredentials(creds)
	client.APIVersion = "/v2"
	if client.HTTPClient != nil {
		client.HTTPClient.Timeout = 180 * time.Second
	}
	baseURL, _ := cmd.Flags().GetString("base-url")
	if baseURL != "" {
		client.BaseURL = baseURL
	}
	return client, nil
}

func buildPackageFirewallRequest(cmd *cobra.Command, args []string) (builtPackageFirewallRequest, error) {
	args = normalizePackageFirewallBoolArgs(cmd, args)
	if len(args) == 1 {
		return builtPackageFirewallRequest{}, fmt.Errorf("package-firewall mirror form requires both <ecosystem> and <url>")
	}
	if len(args) > 2 {
		return builtPackageFirewallRequest{}, fmt.Errorf("package-firewall accepts either zero positionals or <ecosystem> <url>")
	}

	if changed(cmd, "enable") && changed(cmd, "disable") {
		return builtPackageFirewallRequest{}, fmt.Errorf("--enable and --disable are mutually exclusive")
	}

	policyFlags := []string{
		"cvss-threshold", "epss-threshold", "cess-threshold",
		"block-malware", "block-eol", "block-kev", "block-weaponized-exploits",
		"block-active-exploits", "block-poc-exploits", "block-bad-actors",
		"cooldown-days", "version-lag",
	}
	mirrorFlags := []string{"priority", "enable", "disable"}

	if len(args) == 2 {
		if name := firstChanged(cmd, policyFlags); name != "" {
			return builtPackageFirewallRequest{}, fmt.Errorf("--%s is only valid when setting org-wide package-firewall policy", name)
		}
		return buildPackageFirewallMirrorRequest(cmd, args)
	}

	if name := firstChanged(cmd, mirrorFlags); name != "" {
		return builtPackageFirewallRequest{}, fmt.Errorf("--%s is only valid when setting a package-firewall mirror", name)
	}
	return buildPackageFirewallPolicyRequest(cmd)
}

func buildPackageFirewallMirrorRequest(cmd *cobra.Command, args []string) (builtPackageFirewallRequest, error) {
	eco := strings.TrimSpace(args[0])
	rawURL := strings.TrimSpace(args[1])
	if eco == "" {
		return builtPackageFirewallRequest{}, fmt.Errorf("ecosystem is required")
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return builtPackageFirewallRequest{}, fmt.Errorf("mirror url must be an absolute URL, got %q", rawURL)
	}

	req := vdb.CliPackageFirewallMirrorRequest{
		Ecosystem: eco,
		URL:       rawURL,
	}
	if changed(cmd, "priority") {
		priority, _ := cmd.Flags().GetInt("priority")
		if priority < 0 {
			return builtPackageFirewallRequest{}, fmt.Errorf("--priority must be greater than or equal to 0")
		}
		req.Priority = &priority
	}
	if changed(cmd, "enable") {
		v := true
		req.IsActive = &v
	}
	if changed(cmd, "disable") {
		v := false
		req.IsActive = &v
	}
	return builtPackageFirewallRequest{Kind: packageFirewallMirrorRequest, Mirror: req}, nil
}

func buildPackageFirewallPolicyRequest(cmd *cobra.Command) (builtPackageFirewallRequest, error) {
	req := vdb.CliPackageFirewallConfigRequest{}

	if changed(cmd, "cvss-threshold") {
		v, _ := cmd.Flags().GetFloat64("cvss-threshold")
		if v < 0 || v > 10 {
			return builtPackageFirewallRequest{}, fmt.Errorf("--cvss-threshold must be between 0 and 10")
		}
		req.CvssThreshold = &v
	}
	if changed(cmd, "epss-threshold") {
		v, _ := cmd.Flags().GetFloat64("epss-threshold")
		if v < 0 || v > 1 {
			return builtPackageFirewallRequest{}, fmt.Errorf("--epss-threshold must be between 0 and 1")
		}
		req.EpssThreshold = &v
	}
	if changed(cmd, "cess-threshold") {
		v, _ := cmd.Flags().GetFloat64("cess-threshold")
		if v < 0 || v > 10 {
			return builtPackageFirewallRequest{}, fmt.Errorf("--cess-threshold must be between 0 and 10")
		}
		req.CessThreshold = &v
	}
	if changed(cmd, "block-malware") {
		v, _ := cmd.Flags().GetBool("block-malware")
		req.BlockMalware = &v
	}
	if changed(cmd, "block-eol") {
		v, _ := cmd.Flags().GetBool("block-eol")
		req.BlockEol = &v
	}
	if changed(cmd, "block-kev") {
		v, _ := cmd.Flags().GetBool("block-kev")
		req.BlockKev = &v
	}
	if changed(cmd, "block-weaponized-exploits") {
		v, _ := cmd.Flags().GetBool("block-weaponized-exploits")
		req.BlockWeaponized = &v
	}
	if changed(cmd, "block-active-exploits") {
		v, _ := cmd.Flags().GetBool("block-active-exploits")
		req.BlockActive = &v
	}
	if changed(cmd, "block-poc-exploits") {
		v, _ := cmd.Flags().GetBool("block-poc-exploits")
		req.BlockPoc = &v
	}
	if changed(cmd, "block-bad-actors") {
		v, _ := cmd.Flags().GetBool("block-bad-actors")
		req.BlockBadActors = &v
	}
	if changed(cmd, "cooldown-days") {
		v, _ := cmd.Flags().GetInt("cooldown-days")
		if v < 0 {
			return builtPackageFirewallRequest{}, fmt.Errorf("--cooldown-days must be greater than or equal to 0")
		}
		req.CooldownDays = &v
	}
	if changed(cmd, "version-lag") {
		v, _ := cmd.Flags().GetInt("version-lag")
		if v < 0 {
			return builtPackageFirewallRequest{}, fmt.Errorf("--version-lag must be greater than or equal to 0")
		}
		req.VersionLag = &v
	}

	return builtPackageFirewallRequest{Kind: packageFirewallPolicyRequest, Config: req}, nil
}

func newConfigSetEolPolicyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "eol-policy",
		Short: "Set the org-wide EOL severity quality gate",
		Long: `Set the org-wide End-of-Life (EOL) severity quality-gate policy. Each EOL
proximity bucket maps a dependency to a finding severity during SCA scans.

  vulnetix config set eol-policy --this-quarter-severity high --retired-severity critical

Buckets are relative to standard calendar quarters (Q1 Jan–Mar … Q4 Oct–Dec).
A severity of "skip" disables findings for that bucket. Setting any policy
opts the org in to synthetic EOL findings.`,
		Args: cobra.NoArgs,
		RunE: runConfigSetEolPolicy,
	}

	cmd.Flags().String("next-quarter-severity", "", "Severity for dependencies reaching EOL next calendar quarter (skip, low, medium, high, critical)")
	cmd.Flags().String("this-quarter-severity", "", "Severity for dependencies reaching EOL this calendar quarter (skip, low, medium, high, critical)")
	cmd.Flags().String("within-30-days-severity", "", "Severity for dependencies reaching EOL within 30 days (skip, low, medium, high, critical)")
	cmd.Flags().String("retired-severity", "", "Severity for dependencies already past EOL (skip, low, medium, high, critical)")
	cmd.Flags().String("base-url", vdb.DefaultBaseURL, "VDB API base URL")
	cmd.Flags().StringP("output", "o", "pretty", "Output format (pretty, json)")

	for _, name := range []string{"next-quarter-severity", "this-quarter-severity", "within-30-days-severity", "retired-severity"} {
		_ = cmd.RegisterFlagCompletionFunc(name, cobra.FixedCompletions(eolPolicySeverities, cobra.ShellCompDirectiveNoFileComp))
	}
	_ = cmd.RegisterFlagCompletionFunc("output", cobra.FixedCompletions([]string{"pretty", "json"}, cobra.ShellCompDirectiveNoFileComp))
	return cmd
}

func runConfigSetEolPolicy(cmd *cobra.Command, args []string) error {
	output, _ := cmd.Flags().GetString("output")
	switch output {
	case "", "pretty":
		initDisplayContext(cmd, display.ModeText)
	case "json":
		initDisplayContext(cmd, display.ModeJSON)
	default:
		return fmt.Errorf("--output must be one of: pretty, json")
	}

	req := vdb.CliQualityGateConfigRequest{}
	type severityFlag struct {
		flag   string
		target **string
	}
	for _, sf := range []severityFlag{
		{"next-quarter-severity", &req.EolNextQuarterSeverity},
		{"this-quarter-severity", &req.EolThisQuarterSeverity},
		{"within-30-days-severity", &req.EolWithin30DaysSeverity},
		{"retired-severity", &req.EolRetiredSeverity},
	} {
		if !changed(cmd, sf.flag) {
			continue
		}
		v, _ := cmd.Flags().GetString(sf.flag)
		v = strings.TrimSpace(v)
		if err := validateSeverity(sf.flag, v); err != nil {
			return err
		}
		value := v
		*sf.target = &value
	}

	client, err := newPackageFirewallConfigClient(cmd)
	if err != nil {
		return err
	}

	ctx := display.FromCommand(cmd)
	resp, err := client.CliQualityGateConfig(envForCli(), req)
	if err != nil {
		return err
	}
	if ctx.IsJSON() {
		return ctx.Logger.ResultJSON(resp.Data)
	}
	ctx.Logger.Result(renderPackageFirewallResult(ctx, "EOL policy updated", resp.Data))
	return nil
}

func newConfigSetQualityGateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "quality-gate",
		Short: "Set the org-wide CLI scan quality-gate enforcement policy",
		Long: `Set the org-wide quality-gate enforcement policy applied to authenticated
CLI scans. A set org value overrides the corresponding scan flag — org policy
always wins — so use this to enforce a baseline across every CI pipeline.

  vulnetix config set quality-gate --severity high --block-malware true --cooldown 3

Each flag takes a value; only the flags you pass are updated and the rest keep
their stored value. Pass 'null' as a flag's value to unset that setting entirely
for the org — members then fall back to their own scan flags / builtin defaults:

  vulnetix config set quality-gate --severity null --cooldown null`,
		Args: cobra.NoArgs,
		RunE: runConfigSetQualityGate,
	}

	cmd.Flags().String("block-eol", "", "Block end-of-life packages (true, false, or 'null' to unset for the org)")
	cmd.Flags().String("block-malware", "", "Block malicious packages (true, false, or 'null' to unset for the org)")
	cmd.Flags().String("block-unpinned", "", "Block unpinned dependencies (true, false, or 'null' to unset for the org)")
	cmd.Flags().String("cooldown", "", "Minimum package age in days (integer >= 0, or 'null' to unset for the org)")
	cmd.Flags().String("version-lag", "", "Required version lag before allowing packages (integer >= 0, or 'null' to unset for the org)")
	cmd.Flags().String("sca-autofix-max-major-bump", "", "Maximum major-version bump SCA autofix may apply (integer >= 0, or 'null' to unset for the org)")
	cmd.Flags().String("exploits", "", "Exploit maturity gate (poc, active, weaponized, or 'null' to unset for the org)")
	cmd.Flags().String("severity", "", "Severity gate (low, medium, high, critical, or 'null' to unset for the org)")
	cmd.Flags().String("sca-autofix-strategy", "", "SCA autofix target strategy (latest, safest, stable, or 'null' to unset for the org)")
	cmd.Flags().String("base-url", vdb.DefaultBaseURL, "VDB API base URL")
	cmd.Flags().StringP("output", "o", "pretty", "Output format (pretty, json)")

	boolNullComp := cobra.FixedCompletions([]string{"true", "false", "null"}, cobra.ShellCompDirectiveNoFileComp)
	for _, f := range []string{"block-eol", "block-malware", "block-unpinned"} {
		_ = cmd.RegisterFlagCompletionFunc(f, boolNullComp)
	}
	withNull := func(vals []string) []string { return append(append([]string{}, vals...), "null") }
	_ = cmd.RegisterFlagCompletionFunc("exploits", cobra.FixedCompletions(withNull(qualityGateExploits), cobra.ShellCompDirectiveNoFileComp))
	_ = cmd.RegisterFlagCompletionFunc("severity", cobra.FixedCompletions(withNull(qualityGateSeverities), cobra.ShellCompDirectiveNoFileComp))
	_ = cmd.RegisterFlagCompletionFunc("sca-autofix-strategy", cobra.FixedCompletions(withNull(qualityGateAutofixStrats), cobra.ShellCompDirectiveNoFileComp))
	_ = cmd.RegisterFlagCompletionFunc("output", cobra.FixedCompletions([]string{"pretty", "json"}, cobra.ShellCompDirectiveNoFileComp))
	return cmd
}

func runConfigSetQualityGate(cmd *cobra.Command, args []string) error {
	output, _ := cmd.Flags().GetString("output")
	switch output {
	case "", "pretty":
		initDisplayContext(cmd, display.ModeText)
	case "json":
		initDisplayContext(cmd, display.ModeJSON)
	default:
		return fmt.Errorf("--output must be one of: pretty, json")
	}

	req := vdb.CliQualityGateConfigRequest{}

	// Each enforcement flag is a string so it can carry a typed value OR the
	// literal "null" to unset (clear) that setting for the org. A changed flag
	// with value "null" adds the column to req.Clear; any other value is parsed
	// and validated for its type. Unchanged flags are omitted (preserve stored).
	const qgNull = "null"

	for _, bf := range []struct {
		flag, col string
		dst       **bool
	}{
		{"block-eol", "blockEol", &req.BlockEol},
		{"block-malware", "blockMalware", &req.BlockMalware},
		{"block-unpinned", "blockUnpinned", &req.BlockUnpinned},
	} {
		if !changed(cmd, bf.flag) {
			continue
		}
		raw, _ := cmd.Flags().GetString(bf.flag)
		raw = strings.ToLower(strings.TrimSpace(raw))
		if raw == qgNull {
			req.Clear = append(req.Clear, bf.col)
			continue
		}
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("--%s must be true, false, or null", bf.flag)
		}
		val := b
		*bf.dst = &val
	}

	for _, nf := range []struct {
		flag, col string
		dst       **int
	}{
		{"cooldown", "cooldown", &req.Cooldown},
		{"version-lag", "versionLag", &req.VersionLag},
		{"sca-autofix-max-major-bump", "scaAutofixMaxMajorBump", &req.ScaAutofixMaxMajorBump},
	} {
		if !changed(cmd, nf.flag) {
			continue
		}
		raw, _ := cmd.Flags().GetString(nf.flag)
		raw = strings.ToLower(strings.TrimSpace(raw))
		if raw == qgNull {
			req.Clear = append(req.Clear, nf.col)
			continue
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			return fmt.Errorf("--%s must be an integer >= 0, or null", nf.flag)
		}
		val := n
		*nf.dst = &val
	}

	for _, ef := range []struct {
		flag, col string
		enum      []string
		dst       **string
	}{
		{"exploits", "exploits", qualityGateExploits, &req.Exploits},
		{"severity", "severity", qualityGateSeverities, &req.Severity},
		{"sca-autofix-strategy", "scaAutofixStrategy", qualityGateAutofixStrats, &req.ScaAutofixStrategy},
	} {
		if !changed(cmd, ef.flag) {
			continue
		}
		raw, _ := cmd.Flags().GetString(ef.flag)
		raw = strings.ToLower(strings.TrimSpace(raw))
		if raw == qgNull {
			req.Clear = append(req.Clear, ef.col)
			continue
		}
		if err := validateEnum(ef.flag, raw, ef.enum); err != nil {
			return err
		}
		val := raw
		*ef.dst = &val
	}

	client, err := newPackageFirewallConfigClient(cmd)
	if err != nil {
		return err
	}

	ctx := display.FromCommand(cmd)
	resp, err := client.CliQualityGateConfig(envForCli(), req)
	if err != nil {
		return err
	}
	if ctx.IsJSON() {
		return ctx.Logger.ResultJSON(resp.Data)
	}
	ctx.Logger.Result(renderPackageFirewallResult(ctx, "Quality gate policy updated", resp.Data))
	return nil
}

func newConfigGetQualityGateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "quality-gate",
		Short: "Show the org-wide CLI scan quality-gate enforcement policy",
		Long: `Display the org-wide quality-gate enforcement policy applied to authenticated
CLI scans. Settings the org has not configured show as "not set" and leave the
caller's scan flag (or builtin default) in effect.`,
		Args: cobra.NoArgs,
		RunE: runConfigGetQualityGate,
	}
	cmd.Flags().String("base-url", vdb.DefaultBaseURL, "VDB API base URL")
	cmd.Flags().StringP("output", "o", "pretty", "Output format (pretty, json)")
	_ = cmd.RegisterFlagCompletionFunc("output", cobra.FixedCompletions([]string{"pretty", "json"}, cobra.ShellCompDirectiveNoFileComp))
	return cmd
}

func runConfigGetQualityGate(cmd *cobra.Command, args []string) error {
	output, _ := cmd.Flags().GetString("output")
	switch output {
	case "", "pretty":
		initDisplayContext(cmd, display.ModeText)
	case "json":
		initDisplayContext(cmd, display.ModeJSON)
	default:
		return fmt.Errorf("--output must be one of: pretty, json")
	}

	client, err := newPackageFirewallConfigClient(cmd)
	if err != nil {
		return err
	}

	ctx := display.FromCommand(cmd)
	resp, err := client.CliQualityGateGet(envForCli())
	if err != nil {
		return err
	}
	if ctx.IsJSON() {
		return ctx.Logger.ResultJSON(resp.Data)
	}
	ctx.Logger.Result(renderQualityGateGet(ctx, resp.Data))
	return nil
}

// renderQualityGateGet formats the {config} response from cli.quality-gate-get
// into a key/value block of the 9 enforcement settings, showing "not set" for
// any field the org left null. A nil config means the org has no policy row at
// all (the gate is off for CLI scans).
func renderQualityGateGet(ctx *display.Context, data map[string]any) string {
	t := ctx.Term
	var b strings.Builder

	b.WriteString(display.Subheader(t, "Quality gate enforcement policy") + "\n")
	config, _ := data["config"].(map[string]any)
	if config == nil {
		b.WriteString("  No policy configured — scan flags and builtin defaults apply.\n")
		return strings.TrimRight(b.String(), "\n")
	}
	b.WriteString(display.KeyValue(t, []display.KVPair{
		{Key: "Block EOL", Value: qgBool(config, "blockEol")},
		{Key: "Block malware", Value: qgBool(config, "blockMalware")},
		{Key: "Block unpinned", Value: qgBool(config, "blockUnpinned")},
		{Key: "Cooldown days", Value: qgInt(config, "cooldown")},
		{Key: "Version lag", Value: qgInt(config, "versionLag")},
		{Key: "SCA autofix max major bump", Value: qgInt(config, "scaAutofixMaxMajorBump")},
		{Key: "Exploits", Value: qgString(config, "exploits")},
		{Key: "Severity", Value: qgString(config, "severity")},
		{Key: "SCA autofix strategy", Value: qgString(config, "scaAutofixStrategy")},
	}))
	return strings.TrimRight(b.String(), "\n")
}

// qgBool / qgInt / qgString render a nullable enforcement field, showing
// "not set" when the org left it null (absent / JSON null in the config map).
func qgBool(m map[string]any, key string) string {
	if v, ok := m[key].(bool); ok {
		if v {
			return "Yes"
		}
		return "No"
	}
	return "not set"
}

func qgInt(m map[string]any, key string) string {
	if v, ok := m[key].(float64); ok {
		return fmt.Sprintf("%d", int(v))
	}
	return "not set"
}

func qgString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok && v != "" {
		return v
	}
	return "not set"
}

func newConfigGetPackageFirewallCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "package-firewall",
		Short: "Show Package Firewall policy and mirrors",
		Long: `Display the org-wide Vulnetix Package Firewall policy and every configured
mirror across all ecosystems.`,
		Args: cobra.NoArgs,
		RunE: runConfigGetPackageFirewall,
	}
	cmd.Flags().String("base-url", vdb.DefaultBaseURL, "VDB API base URL")
	cmd.Flags().StringP("output", "o", "pretty", "Output format (pretty, json)")
	_ = cmd.RegisterFlagCompletionFunc("output", cobra.FixedCompletions([]string{"pretty", "json"}, cobra.ShellCompDirectiveNoFileComp))
	return cmd
}

func runConfigGetPackageFirewall(cmd *cobra.Command, args []string) error {
	output, _ := cmd.Flags().GetString("output")
	switch output {
	case "", "pretty":
		initDisplayContext(cmd, display.ModeText)
	case "json":
		initDisplayContext(cmd, display.ModeJSON)
	default:
		return fmt.Errorf("--output must be one of: pretty, json")
	}

	client, err := newPackageFirewallConfigClient(cmd)
	if err != nil {
		return err
	}

	ctx := display.FromCommand(cmd)
	resp, err := client.CliPackageFirewallGet(envForCli())
	if err != nil {
		return err
	}
	if ctx.IsJSON() {
		return ctx.Logger.ResultJSON(resp.Data)
	}
	ctx.Logger.Result(renderPackageFirewallGet(ctx, resp.Data))
	return nil
}

// renderPackageFirewallGet formats the {config, mirrors} response from
// cli.package-firewall-get into a policy key/value block plus a mirrors table.
// Numeric fields arrive as float64 (JSON), so each accessor narrows as needed.
func renderPackageFirewallGet(ctx *display.Context, data map[string]any) string {
	t := ctx.Term
	var b strings.Builder

	b.WriteString(display.Subheader(t, "Package Firewall policy") + "\n")
	config, _ := data["config"].(map[string]any)
	if config == nil {
		b.WriteString("  No policy configured — proxy defaults apply.\n")
	} else {
		b.WriteString(display.KeyValue(t, []display.KVPair{
			{Key: "CVSS threshold", Value: pfwFloat(config, "cvssThreshold")},
			{Key: "EPSS threshold", Value: pfwFloat(config, "epssThreshold")},
			{Key: "CESS threshold", Value: pfwFloat(config, "cessThreshold")},
			{Key: "Block malware", Value: pfwBool(config, "blockMalware")},
			{Key: "Block EOL", Value: pfwBool(config, "blockEol")},
			{Key: "Block KEV", Value: pfwBool(config, "blockKev")},
			{Key: "Block weaponized exploits", Value: pfwBool(config, "blockWeaponized")},
			{Key: "Block active exploits", Value: pfwBool(config, "blockActive")},
			{Key: "Block PoC exploits", Value: pfwBool(config, "blockPoc")},
			{Key: "Block bad actors", Value: pfwBool(config, "blockBadActors")},
			{Key: "Cooldown days", Value: pfwInt(config, "cooldownDays")},
			{Key: "Version lag", Value: pfwInt(config, "versionLag")},
		}))
	}

	b.WriteString("\n" + display.Subheader(t, "Mirrors") + "\n")
	mirrors := pfwMirrors(data["mirrors"])
	if len(mirrors) == 0 {
		b.WriteString("  No mirrors configured.\n")
		return strings.TrimRight(b.String(), "\n")
	}
	sort.SliceStable(mirrors, func(i, j int) bool {
		ei, ej := pfwString(mirrors[i], "ecosystem"), pfwString(mirrors[j], "ecosystem")
		if ei != ej {
			return ei < ej
		}
		return pfwIntValue(mirrors[i], "priority") < pfwIntValue(mirrors[j], "priority")
	})
	cols := []display.Column{
		{Header: "Ecosystem"},
		{Header: "Priority", Align: display.AlignRight},
		{Header: "Active"},
		{Header: "URL"},
	}
	rows := make([][]string, 0, len(mirrors))
	for _, m := range mirrors {
		rows = append(rows, []string{
			pfwString(m, "ecosystem"),
			pfwInt(m, "priority"),
			pfwBool(m, "isActive"),
			pfwString(m, "url"),
		})
	}
	b.WriteString(display.Table(t, cols, rows))
	return strings.TrimRight(b.String(), "\n")
}

func newConfigGetEolPolicyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "eol-policy",
		Short: "Show the org-wide EOL severity quality gate",
		Long: `Display the org-wide End-of-Life (EOL) severity quality-gate policy. When no
policy is configured the org has not opted in and no EOL findings are created.`,
		Args: cobra.NoArgs,
		RunE: runConfigGetEolPolicy,
	}
	cmd.Flags().String("base-url", vdb.DefaultBaseURL, "VDB API base URL")
	cmd.Flags().StringP("output", "o", "pretty", "Output format (pretty, json)")
	_ = cmd.RegisterFlagCompletionFunc("output", cobra.FixedCompletions([]string{"pretty", "json"}, cobra.ShellCompDirectiveNoFileComp))
	return cmd
}

func runConfigGetEolPolicy(cmd *cobra.Command, args []string) error {
	output, _ := cmd.Flags().GetString("output")
	switch output {
	case "", "pretty":
		initDisplayContext(cmd, display.ModeText)
	case "json":
		initDisplayContext(cmd, display.ModeJSON)
	default:
		return fmt.Errorf("--output must be one of: pretty, json")
	}

	client, err := newPackageFirewallConfigClient(cmd)
	if err != nil {
		return err
	}

	ctx := display.FromCommand(cmd)
	resp, err := client.CliQualityGateGet(envForCli())
	if err != nil {
		return err
	}
	if ctx.IsJSON() {
		return ctx.Logger.ResultJSON(resp.Data)
	}
	ctx.Logger.Result(renderEolPolicyGet(ctx, resp.Data))
	return nil
}

// renderEolPolicyGet formats the {config} response from cli.quality-gate-get
// into a severity key/value block, or a "not configured" hint when the org has
// no policy (no row → no EOL findings).
func renderEolPolicyGet(ctx *display.Context, data map[string]any) string {
	t := ctx.Term
	var b strings.Builder

	b.WriteString(display.Subheader(t, "EOL severity policy") + "\n")
	config, _ := data["config"].(map[string]any)
	if config == nil {
		b.WriteString("  No policy configured — defaults apply.\n")
		return strings.TrimRight(b.String(), "\n")
	}
	b.WriteString(display.KeyValue(t, []display.KVPair{
		{Key: "Next quarter", Value: pfwString(config, "eolNextQuarterSeverity")},
		{Key: "This quarter", Value: pfwString(config, "eolThisQuarterSeverity")},
		{Key: "Within 30 days", Value: pfwString(config, "eolWithin30DaysSeverity")},
		{Key: "Retired", Value: pfwString(config, "eolRetiredSeverity")},
	}))
	return strings.TrimRight(b.String(), "\n")
}

func pfwMirrors(v any) []map[string]any {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(list))
	for _, item := range list {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func pfwFloat(m map[string]any, key string) string {
	if v, ok := m[key].(float64); ok {
		return fmt.Sprintf("%g", v)
	}
	return "0"
}

func pfwInt(m map[string]any, key string) string {
	return fmt.Sprintf("%d", pfwIntValue(m, key))
}

func pfwIntValue(m map[string]any, key string) int {
	if v, ok := m[key].(float64); ok {
		return int(v)
	}
	return 0
}

func pfwBool(m map[string]any, key string) string {
	if v, ok := m[key].(bool); ok && v {
		return "Yes"
	}
	return "No"
}

func pfwString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func renderPackageFirewallResult(ctx *display.Context, title string, data map[string]any) string {
	pairs := []display.KVPair{{Key: "Status", Value: title}}
	if source := auth.CredentialSource(); source != "none" {
		pairs = append(pairs, display.KVPair{Key: "Credential source", Value: source})
	}

	keys := make([]string, 0, len(data))
	for key := range data {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		pairs = append(pairs, display.KVPair{Key: key, Value: fmt.Sprint(data[key])})
	}
	return display.KeyValue(ctx.Term, pairs)
}

func changed(cmd *cobra.Command, name string) bool {
	return cmd.Flags().Changed(name)
}

func firstChanged(cmd *cobra.Command, names []string) string {
	for _, name := range names {
		if changed(cmd, name) {
			return name
		}
	}
	return ""
}

func normalizePackageFirewallBoolArgs(cmd *cobra.Command, args []string) []string {
	if len(args) == 0 {
		return args
	}
	for _, arg := range args {
		if !isBoolLiteral(arg) {
			return args
		}
	}

	policyBoolFlags := map[string]bool{
		"block-malware":             true,
		"block-eol":                 true,
		"block-kev":                 true,
		"block-weaponized-exploits": true,
		"block-active-exploits":     true,
		"block-poc-exploits":        true,
		"block-bad-actors":          true,
	}
	var changedPolicyBoolFlags []string
	cmd.Flags().Visit(func(flag *pflag.Flag) {
		if policyBoolFlags[flag.Name] {
			changedPolicyBoolFlags = append(changedPolicyBoolFlags, flag.Name)
		}
	})
	if len(changedPolicyBoolFlags) == 0 || len(args) > len(changedPolicyBoolFlags) {
		return args
	}
	for i, arg := range args {
		_ = cmd.Flags().Set(changedPolicyBoolFlags[i], arg)
	}
	return nil
}

func isBoolLiteral(s string) bool {
	return s == "true" || s == "false"
}

var configGetCmd = &cobra.Command{
	Use:   "get",
	Short: "Show Vulnetix configuration",
}

func init() {
	configSetCmd.AddCommand(newConfigSetPackageFirewallCommand())
	configSetCmd.AddCommand(newConfigSetEolPolicyCommand())
	configSetCmd.AddCommand(newConfigSetQualityGateCommand())
	configSetCmd.AddCommand(newConfigSetAiFirewallCommand())
	configGetCmd.AddCommand(newConfigGetPackageFirewallCommand())
	configGetCmd.AddCommand(newConfigGetEolPolicyCommand())
	configGetCmd.AddCommand(newConfigGetQualityGateCommand())
	configGetCmd.AddCommand(newConfigGetAiFirewallCommand())
	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configGetCmd)
	rootCmd.AddCommand(configCmd)
}
