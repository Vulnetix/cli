package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// AI Firewall (guardrails.vulnetix.com) configuration commands. The gateway
// proxies OpenAI-compatible chat completions per provider path prefix
// (https://guardrails.vulnetix.com/{providerSlug}/v1/chat/completions) with
// the caller's own provider API key; these commands manage the org policy it
// enforces: provider allow/deny, model allow/deny lists, and content
// guardrails. Completely separate from the Package Firewall feature.

func newConfigGetAiFirewallCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ai-firewall",
		Short: "Show AI Firewall providers, model lists, and guardrails",
		Long: `Display the org-wide Vulnetix AI Firewall policy: the provider catalog with
this org's allow/deny association, the model allow/deny lists, and the content
guardrails enforced inline by https://guardrails.vulnetix.com.`,
		Args: cobra.NoArgs,
		RunE: runConfigGetAiFirewall,
	}
	cmd.Flags().String("base-url", vdb.DefaultBaseURL, "VDB API base URL")
	cmd.Flags().StringP("output", "o", "pretty", "Output format (pretty, json)")
	_ = cmd.RegisterFlagCompletionFunc("output", cobra.FixedCompletions([]string{"pretty", "json"}, cobra.ShellCompDirectiveNoFileComp))
	return cmd
}

func runConfigGetAiFirewall(cmd *cobra.Command, args []string) error {
	if err := initAiFirewallOutput(cmd); err != nil {
		return err
	}
	client, err := newPackageFirewallConfigClient(cmd)
	if err != nil {
		return err
	}

	ctx := display.FromCommand(cmd)
	resp, err := client.CliAiFirewallGet(envForCli())
	if err != nil {
		return err
	}
	if ctx.IsJSON() {
		return ctx.Logger.ResultJSON(resp.Data)
	}
	ctx.Logger.Result(renderAiFirewallGet(ctx, resp.Data))
	return nil
}

func newConfigSetAiFirewallCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ai-firewall",
		Short: "Configure AI Firewall providers, model lists, and guardrails",
		Long: `Configure the org-wide Vulnetix AI Firewall (https://guardrails.vulnetix.com)
policy. Point OpenAI SDKs at https://guardrails.vulnetix.com/{providerSlug}
with your own provider API key as the bearer token and your org UUID in the
X-Organisation-UUID header; the gateway enforces this policy inline.`,
	}
	cmd.AddCommand(newConfigSetAiFirewallProviderCommand())
	cmd.AddCommand(newConfigSetAiFirewallModelCommand())
	cmd.AddCommand(newConfigSetAiFirewallGuardrailCommand())
	return cmd
}

func newConfigSetAiFirewallProviderCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "provider <slug>",
		Short: "Allow, deny, or clear a provider for this org",
		Long: `Set the org's allow/deny association for an AI provider (by slug, e.g.
"openrouter"). With no association a provider is usable (default-allow);
--deny blocks every request through it; --clear removes the association.`,
		Args: cobra.ExactArgs(1),
		RunE: runConfigSetAiFirewallProvider,
	}
	cmd.Flags().Bool("allow", false, "Explicitly allow the provider")
	cmd.Flags().Bool("deny", false, "Deny the provider for this org")
	cmd.Flags().Bool("clear", false, "Remove the org's association (back to default-allow)")
	addAiFirewallCommonFlags(cmd)
	return cmd
}

func runConfigSetAiFirewallProvider(cmd *cobra.Command, args []string) error {
	if err := initAiFirewallOutput(cmd); err != nil {
		return err
	}
	action, err := aiFirewallActionFromFlags(cmd, map[string]string{"allow": "allow", "deny": "deny", "clear": "clear"})
	if err != nil {
		return err
	}

	client, err := newPackageFirewallConfigClient(cmd)
	if err != nil {
		return err
	}
	ctx := display.FromCommand(cmd)
	resp, err := client.CliAiFirewallProvider(envForCli(), vdb.CliAiFirewallProviderRequest{
		Slug:   args[0],
		Action: action,
	})
	if err != nil {
		return err
	}
	if ctx.IsJSON() {
		return ctx.Logger.ResultJSON(resp.Data)
	}
	ctx.Logger.Result(renderPackageFirewallResult(ctx, "AI Firewall provider policy updated", resp.Data))
	return nil
}

func newConfigSetAiFirewallModelCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "model <model-slug>",
		Short: "Add or remove a model allow/deny entry",
		Long: `Add a model (by its provider model id, e.g. "openai/gpt-4o") to the org's
allow or deny list, or remove its entry. Scope with --provider <slug> for one
provider, or --any-provider to expand across every provider whose catalog
lists the model. If the org has any allow entries for a provider, that
provider runs in allowlist mode: only allowed models pass.`,
		Args: cobra.ExactArgs(1),
		RunE: runConfigSetAiFirewallModel,
	}
	cmd.Flags().Bool("allow", false, "Add the model to the allow list")
	cmd.Flags().Bool("deny", false, "Add the model to the deny list")
	cmd.Flags().Bool("remove", false, "Remove the model's allow/deny entry")
	cmd.Flags().String("provider", "", "Provider slug the entry applies to")
	cmd.Flags().Bool("any-provider", false, "Apply across all providers listing this model")
	addAiFirewallCommonFlags(cmd)
	return cmd
}

func runConfigSetAiFirewallModel(cmd *cobra.Command, args []string) error {
	if err := initAiFirewallOutput(cmd); err != nil {
		return err
	}
	action, err := aiFirewallActionFromFlags(cmd, map[string]string{"allow": "allow", "deny": "deny", "remove": "remove"})
	if err != nil {
		return err
	}
	provider, _ := cmd.Flags().GetString("provider")
	anyProvider, _ := cmd.Flags().GetBool("any-provider")
	if provider == "" && !anyProvider {
		return fmt.Errorf("specify --provider <slug> or --any-provider")
	}
	if provider != "" && anyProvider {
		return fmt.Errorf("--provider and --any-provider are mutually exclusive")
	}

	client, err := newPackageFirewallConfigClient(cmd)
	if err != nil {
		return err
	}
	ctx := display.FromCommand(cmd)
	resp, err := client.CliAiFirewallModel(envForCli(), vdb.CliAiFirewallModelRequest{
		Slug:        args[0],
		Provider:    provider,
		AnyProvider: anyProvider,
		Action:      action,
	})
	if err != nil {
		return err
	}
	if ctx.IsJSON() {
		return ctx.Logger.ResultJSON(resp.Data)
	}
	ctx.Logger.Result(renderPackageFirewallResult(ctx, "AI Firewall model policy updated", resp.Data))
	return nil
}

func newConfigSetAiFirewallGuardrailCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "guardrail <name>",
		Short: "Create, update, or delete a content guardrail",
		Long: `Create or update a content guardrail enforced inline on every proxied
request. Rule types: blocked_pattern (pattern = regex), max_messages
(pattern = integer cap), pii_redact (pattern = optional regex; empty uses the
built-in email/card/SSN/phone detectors). Actions: block, redact, flag.
Update or delete an existing guardrail by --uuid.`,
		Args: cobra.ExactArgs(1),
		RunE: runConfigSetAiFirewallGuardrail,
	}
	cmd.Flags().String("uuid", "", "Existing guardrail UUID (update/delete)")
	cmd.Flags().String("rule-type", "", "Rule type: blocked_pattern, max_messages, pii_redact")
	cmd.Flags().String("action", "", "Action on match: block, redact, flag")
	cmd.Flags().String("pattern", "", "Regex (blocked_pattern/pii_redact) or integer (max_messages)")
	cmd.Flags().Int("priority", 0, "Evaluation order, lowest first (default 100)")
	cmd.Flags().Bool("enable", false, "Enable the guardrail")
	cmd.Flags().Bool("disable", false, "Disable the guardrail")
	cmd.Flags().Bool("delete", false, "Delete the guardrail (requires --uuid)")
	addAiFirewallCommonFlags(cmd)
	_ = cmd.RegisterFlagCompletionFunc("rule-type", cobra.FixedCompletions([]string{"blocked_pattern", "max_messages", "pii_redact"}, cobra.ShellCompDirectiveNoFileComp))
	_ = cmd.RegisterFlagCompletionFunc("action", cobra.FixedCompletions([]string{"block", "redact", "flag"}, cobra.ShellCompDirectiveNoFileComp))
	return cmd
}

func runConfigSetAiFirewallGuardrail(cmd *cobra.Command, args []string) error {
	if err := initAiFirewallOutput(cmd); err != nil {
		return err
	}

	req := vdb.CliAiFirewallGuardrailRequest{}
	req.UUID, _ = cmd.Flags().GetString("uuid")
	req.Delete, _ = cmd.Flags().GetBool("delete")
	if req.Delete && req.UUID == "" {
		return fmt.Errorf("--delete requires --uuid")
	}
	name := args[0]
	req.Name = &name
	if changed(cmd, "rule-type") {
		v, _ := cmd.Flags().GetString("rule-type")
		req.RuleType = &v
	}
	if changed(cmd, "action") {
		v, _ := cmd.Flags().GetString("action")
		req.Action = &v
	}
	if changed(cmd, "pattern") {
		v, _ := cmd.Flags().GetString("pattern")
		req.Pattern = &v
	}
	if changed(cmd, "priority") {
		v, _ := cmd.Flags().GetInt("priority")
		req.Priority = &v
	}
	enable, _ := cmd.Flags().GetBool("enable")
	disable, _ := cmd.Flags().GetBool("disable")
	if enable && disable {
		return fmt.Errorf("--enable and --disable are mutually exclusive")
	}
	if enable || disable {
		v := enable
		req.Enabled = &v
	}
	if req.UUID == "" && !req.Delete && req.RuleType == nil {
		return fmt.Errorf("--rule-type is required when creating a guardrail")
	}

	client, err := newPackageFirewallConfigClient(cmd)
	if err != nil {
		return err
	}
	ctx := display.FromCommand(cmd)
	resp, err := client.CliAiFirewallGuardrail(envForCli(), req)
	if err != nil {
		return err
	}
	if ctx.IsJSON() {
		return ctx.Logger.ResultJSON(resp.Data)
	}
	title := "AI Firewall guardrail updated"
	if req.Delete {
		title = "AI Firewall guardrail deleted"
	}
	ctx.Logger.Result(renderPackageFirewallResult(ctx, title, resp.Data))
	return nil
}

func addAiFirewallCommonFlags(cmd *cobra.Command) {
	cmd.Flags().String("base-url", vdb.DefaultBaseURL, "VDB API base URL")
	cmd.Flags().StringP("output", "o", "pretty", "Output format (pretty, json)")
	_ = cmd.RegisterFlagCompletionFunc("output", cobra.FixedCompletions([]string{"pretty", "json"}, cobra.ShellCompDirectiveNoFileComp))
}

func initAiFirewallOutput(cmd *cobra.Command) error {
	output, _ := cmd.Flags().GetString("output")
	switch output {
	case "", "pretty":
		initDisplayContext(cmd, display.ModeText)
	case "json":
		initDisplayContext(cmd, display.ModeJSON)
	default:
		return fmt.Errorf("--output must be one of: pretty, json")
	}
	return nil
}

// aiFirewallActionFromFlags maps exactly one changed boolean flag to its
// action value.
func aiFirewallActionFromFlags(cmd *cobra.Command, flagToAction map[string]string) (string, error) {
	var actions []string
	var flags []string
	for flag, action := range flagToAction {
		flags = append(flags, "--"+flag)
		if v, _ := cmd.Flags().GetBool(flag); v {
			actions = append(actions, action)
		}
	}
	if len(actions) != 1 {
		return "", fmt.Errorf("specify exactly one of %s", strings.Join(flags, ", "))
	}
	return actions[0], nil
}

// renderAiFirewallGet formats the {providers, modelPolicies, guardrails}
// response from cli.ai-firewall-get into three tables.
func renderAiFirewallGet(ctx *display.Context, data map[string]any) string {
	t := ctx.Term
	var b strings.Builder

	b.WriteString(display.Subheader(t, "AI Providers") + "\n")
	providers := aiFirewallList(data["providers"])
	if len(providers) == 0 {
		b.WriteString("  No providers in the catalog.\n")
	} else {
		cols := []display.Column{
			{Header: "Slug"},
			{Header: "Name"},
			{Header: "Enabled"},
			{Header: "Models", Align: display.AlignRight},
			{Header: "Org policy"},
		}
		rows := make([][]string, 0, len(providers))
		for _, p := range providers {
			orgAction := pfwString(p, "orgAction")
			if orgAction == "" {
				orgAction = "default (allow)"
			}
			rows = append(rows, []string{
				pfwString(p, "slug"),
				pfwString(p, "name"),
				pfwBool(p, "globalEnabled"),
				pfwInt(p, "modelCount"),
				orgAction,
			})
		}
		b.WriteString(display.Table(t, cols, rows))
	}

	b.WriteString("\n" + display.Subheader(t, "Model allow/deny lists") + "\n")
	policies := aiFirewallList(data["modelPolicies"])
	if len(policies) == 0 {
		b.WriteString("  No model entries — all active catalog models are allowed.\n")
	} else {
		cols := []display.Column{
			{Header: "Provider"},
			{Header: "Model"},
			{Header: "Action"},
			{Header: "Listed"},
		}
		rows := make([][]string, 0, len(policies))
		for _, m := range policies {
			rows = append(rows, []string{
				pfwString(m, "providerSlug"),
				pfwString(m, "slug"),
				pfwString(m, "action"),
				pfwBool(m, "isActive"),
			})
		}
		b.WriteString(display.Table(t, cols, rows))
	}

	b.WriteString("\n" + display.Subheader(t, "Guardrails") + "\n")
	guardrails := aiFirewallList(data["guardrails"])
	if len(guardrails) == 0 {
		b.WriteString("  No guardrails configured.\n")
		return strings.TrimRight(b.String(), "\n")
	}
	cols := []display.Column{
		{Header: "Priority", Align: display.AlignRight},
		{Header: "Name"},
		{Header: "Rule"},
		{Header: "Action"},
		{Header: "Enabled"},
		{Header: "Pattern"},
	}
	rows := make([][]string, 0, len(guardrails))
	for _, g := range guardrails {
		rows = append(rows, []string{
			pfwInt(g, "priority"),
			pfwString(g, "name"),
			pfwString(g, "ruleType"),
			pfwString(g, "action"),
			pfwBool(g, "enabled"),
			pfwString(g, "pattern"),
		})
	}
	b.WriteString(display.Table(t, cols, rows))
	return strings.TrimRight(b.String(), "\n")
}

func aiFirewallList(v any) []map[string]any {
	items, _ := v.([]any)
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}
