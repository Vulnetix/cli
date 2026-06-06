package cmd

import (
	"fmt"
	"net/url"
	"sort"
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
	configGetCmd.AddCommand(newConfigGetPackageFirewallCommand())
	configCmd.AddCommand(configSetCmd)
	configCmd.AddCommand(configGetCmd)
	rootCmd.AddCommand(configCmd)
}
