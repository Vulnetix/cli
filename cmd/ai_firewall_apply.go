package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/display"
	aifw "github.com/vulnetix/cli/v3/pkg/aifirewall"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// --- baseline ---

func newAiFirewallBaselineCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "baseline",
		Short: "Show the guardrails the server recommends",
		Long: `Print the recommended guardrail set — PII masking, prompt injection, and so on.

The set comes from the server, so the recommendations improve without a CLI
release. It never contains provider or model allow/deny lists: what an org may
call is the org's decision.

Apply it with 'vulnetix ai-firewall apply' and a policy file whose
spec.baseline.enabled is true. Substitute your own set with --catalog.`,
		Args: cobra.NoArgs,
		RunE: runAiFirewallBaseline,
	}
	cmd.Flags().String("ref", "recommended", "Named baseline set")
	cmd.Flags().String("catalog", "", "Use a local baseline file (JSON or YAML) instead of the server's")
	addAiFirewallCommonFlags(cmd)
	return cmd
}

func runAiFirewallBaseline(cmd *cobra.Command, args []string) error {
	if err := initAiFirewallOutput(cmd); err != nil {
		return err
	}
	ctx := display.FromCommand(cmd)

	baseline, note, err := loadBaseline(cmd, false)
	if err != nil {
		return err
	}
	if baseline == nil {
		if ctx.IsJSON() {
			return ctx.Logger.ResultJSON(map[string]any{"available": false, "reason": note})
		}
		ctx.Logger.Result("No baseline available: " + note)
		return nil
	}

	if ctx.IsJSON() {
		return ctx.Logger.ResultJSON(baseline)
	}

	t := ctx.Term
	var b strings.Builder
	b.WriteString(display.Bold(t, "Recommended guardrails") + "\n")
	b.WriteString(display.KeyValue(t, []display.KVPair{
		{Key: "Ref", Value: baseline.Ref},
		{Key: "Version", Value: baseline.Version},
	}) + "\n\n")
	cols := []display.Column{
		{Header: "ID"}, {Header: "Name"}, {Header: "Rule"}, {Header: "Action"},
		{Header: "Priority", Align: display.AlignRight},
	}
	rows := make([][]string, 0, len(baseline.Guardrails))
	for _, g := range baseline.Guardrails {
		rows = append(rows, []string{g.ID, g.Name, g.RuleType, g.Action, fmt.Sprint(g.Priority)})
	}
	b.WriteString(display.Table(t, cols, rows))
	ctx.Logger.Result(strings.TrimRight(b.String(), "\n"))
	return nil
}

// loadBaseline resolves the baseline from --catalog or the server.
//
// A server that does not serve baselines is not an error: this CLI ships before
// the endpoint does, and an org with a perfectly good policy file should not be
// blocked because a recommendation service is unavailable. The caller gets
// (nil, reason, nil) and carries on with the local policy — unless
// --baseline-required, which is what you want in CI, where a silently missing
// baseline would mean silently unenforced rules.
func loadBaseline(cmd *cobra.Command, required bool) (*aifw.Baseline, string, error) {
	catalog, _ := cmd.Flags().GetString("catalog")
	if catalog != "" {
		b, err := aifw.LoadBaselineFile(catalog)
		if err != nil {
			return nil, "", err
		}
		return b, "", nil
	}
	if noBaseline, err := cmd.Flags().GetBool("no-baseline"); err == nil && noBaseline {
		return nil, "disabled with --no-baseline", nil
	}

	ref, _ := cmd.Flags().GetString("ref")
	client, err := newPackageFirewallConfigClient(cmd)
	if err != nil {
		return nil, "", err
	}
	resp, err := client.CliAiFirewallBaseline(envForCli(), vdb.CliAiFirewallBaselineRequest{Ref: ref})
	if err != nil {
		reason := fmt.Sprintf("the server does not serve a guardrail baseline (%v)", err)
		if required {
			return nil, "", fmt.Errorf("--baseline-required: %s", reason)
		}
		return nil, reason, nil
	}

	b := &aifw.Baseline{Version: resp.Data.Version, Ref: resp.Data.Ref}
	for _, g := range resp.Data.Guardrails {
		b.Guardrails = append(b.Guardrails, aifw.BaselineGuardrail{
			ID: g.ID, Name: g.Name, Description: g.Description,
			RuleType: g.RuleType, Action: g.Action, Pattern: g.Pattern,
			Priority: g.Priority, Enabled: g.Enabled, Tags: g.Tags, Severity: g.Severity,
		})
	}
	// A baseline with one bad pattern is rejected whole: applying the rest would
	// leave the org believing it had a complete set when it had a hole.
	if err := b.Compile(); err != nil {
		if required {
			return nil, "", err
		}
		return nil, fmt.Sprintf("the server's baseline is invalid and was not applied (%v)", err), nil
	}
	return b, "", nil
}

// --- apply ---

func newAiFirewallApplyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Reconcile the org's policy from .vulnetix/ai-firewall.yaml",
		Long: `Make the org's AI Firewall policy match a policy file.

Changes are applied in a deliberate order — guardrails, then models, then
providers, then keys, then settings — so that tightening a policy never passes
through a window where a provider is enabled and the guardrails constraining it
are not yet in place.

Objects on the server that the file does not mention are reported as drift and
left alone. --prune deletes them instead; it is off by default because an apply
must not silently destroy a guardrail someone authored in the dashboard.

Run with --dry-run first: it prints the plan and changes nothing.`,
		Args: cobra.NoArgs,
		RunE: runAiFirewallApply,
	}
	cmd.Flags().StringP("file", "f", aifw.DefaultPolicyPath, "Policy file")
	cmd.Flags().Bool("dry-run", false, "Print the plan without changing anything")
	cmd.Flags().Bool("prune", false, "Delete server objects the file does not mention")
	cmd.Flags().Bool("no-baseline", false, "Do not apply the server's recommended guardrails")
	cmd.Flags().Bool("baseline-required", false, "Fail if the baseline cannot be fetched (use in CI)")
	cmd.Flags().String("catalog", "", "Use a local baseline file instead of the server's")
	cmd.Flags().String("ref", "recommended", "Named baseline set")
	cmd.Flags().Bool("force", false, "Apply even when metadata.org does not match the authenticated org")
	addAiFirewallCommonFlags(cmd)
	return cmd
}

func runAiFirewallApply(cmd *cobra.Command, args []string) error {
	if err := initAiFirewallOutput(cmd); err != nil {
		return err
	}
	ctx := display.FromCommand(cmd)

	path, _ := cmd.Flags().GetString("file")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	prune, _ := cmd.Flags().GetBool("prune")
	force, _ := cmd.Flags().GetBool("force")
	required, _ := cmd.Flags().GetBool("baseline-required")

	pf, err := aifw.LoadPolicyFile(path)
	if err != nil {
		return err
	}
	if prune {
		pf.Spec.Prune = true
	}

	client, err := newPackageFirewallConfigClient(cmd)
	if err != nil {
		return err
	}
	resp, err := client.CliAiFirewallState(envForCli())
	if err != nil {
		return err
	}
	state := resp.Data

	orgID, _, _, err := packageFirewallAPIKey(flagString(cmd, "base-url"))
	if err != nil {
		return err
	}
	// The commonest way to do real damage with a policy file is to run it against
	// the wrong org.
	if pf.Metadata.Org != "" && pf.Metadata.Org != orgID && !force {
		return fmt.Errorf("%s declares metadata.org %s, but you are authenticated as %s — pass --force to apply anyway", path, pf.Metadata.Org, orgID)
	}

	// Compose the desired guardrails from the file plus the server's baseline.
	var baselineNote string
	if bs := pf.Spec.Baseline; bs != nil && bs.Enabled {
		baseline, note, err := loadBaseline(cmd, required)
		if err != nil {
			return err
		}
		baselineNote = note
		if baseline != nil {
			pf.Spec.Guardrails = aifw.ComposeGuardrails(pf.Spec.Guardrails, baseline, bs.Exclude)
			baselineNote = fmt.Sprintf("baseline %s (%s) composed in", baseline.Ref, baseline.Version)
		}
	}

	changes := aifw.Plan(*pf, serverStateFrom(state))
	mutating := aifw.Mutating(changes)

	if dryRun {
		if ctx.IsJSON() {
			return ctx.Logger.ResultJSON(map[string]any{
				"dryRun": true, "file": path, "baseline": baselineNote, "changes": changes,
			})
		}
		ctx.Logger.Result(renderAiFirewallPlan(ctx, path, baselineNote, changes, true))
		return nil
	}

	applied, err := executePlan(client, mutating)
	if err != nil {
		return fmt.Errorf("applied %d of %d change(s), then failed: %w", applied, len(mutating), err)
	}

	if ctx.IsJSON() {
		return ctx.Logger.ResultJSON(map[string]any{
			"dryRun": false, "file": path, "baseline": baselineNote,
			"applied": applied, "changes": changes,
		})
	}
	ctx.Logger.Result(renderAiFirewallPlan(ctx, path, baselineNote, changes, false))
	return nil
}

func flagString(cmd *cobra.Command, name string) string {
	v, _ := cmd.Flags().GetString(name)
	return v
}

func serverStateFrom(state vdb.CliAiFirewallState) aifw.ServerState {
	out := aifw.ServerState{
		Providers:   map[string]string{},
		HasKey:      map[string]bool{},
		Models:      map[string]string{},
		Guardrails:  map[string]aifw.ServerGuardrail{},
		LogsEnabled: state.LogsEnabled,
	}
	for _, p := range state.Providers {
		out.Providers[p.Slug] = p.OrgAction
		out.HasKey[p.Slug] = p.HasKey
	}
	for _, m := range state.ModelPolicies {
		out.Models[m.ProviderSlug+"/"+m.Slug] = m.Action
	}
	for _, g := range state.Guardrails {
		out.Guardrails[g.Name] = aifw.ServerGuardrail{
			UUID: g.UUID, RuleType: g.RuleType, Action: g.Action,
			Pattern: g.Pattern, Priority: g.Priority, Enabled: g.Enabled,
		}
	}
	return out
}

// executePlan applies the changes in order, stopping at the first failure and
// reporting how far it got — a half-applied policy the user does not know about
// is the worst outcome available.
func executePlan(client *vdb.Client, changes []aifw.Change) (int, error) {
	env := envForCli()
	for i, c := range changes {
		var err error
		switch c.Kind {
		case aifw.KindGuardrail:
			err = applyGuardrail(client, env, c)
		case aifw.KindModel:
			m := c.Model
			err = errOf(client.CliAiFirewallModel(env, vdb.CliAiFirewallModelRequest{
				Slug: m.Slug, Provider: m.Provider, AnyProvider: m.AnyProvider, Action: m.Action,
			}))
		case aifw.KindProvider:
			err = errOf(client.CliAiFirewallProvider(env, vdb.CliAiFirewallProviderRequest{
				Slug: c.Provider.Slug, Action: providerAction(c.Provider.Action),
			}))
		case aifw.KindKey:
			err = applyKey(client, env, c)
		case aifw.KindSettings:
			err = errOf(client.CliAiFirewallSettings(env, vdb.CliAiFirewallSettingsRequest{
				LogsEnabled: c.Enable,
			}))
		}
		if err != nil {
			return i, fmt.Errorf("%s %s %s: %w", c.Op, c.Kind, c.Target, err)
		}
	}
	return len(changes), nil
}

func applyGuardrail(client *vdb.Client, env vdb.CliEnv, c aifw.Change) error {
	if c.Op == aifw.OpDelete {
		name := c.Target
		return errOf(client.CliAiFirewallGuardrail(env, vdb.CliAiFirewallGuardrailRequest{
			UUID: c.UUID, Name: &name, Delete: true,
		}))
	}
	g := c.Guardrail
	enabled := g.IsEnabled()
	req := vdb.CliAiFirewallGuardrailRequest{
		UUID:     c.UUID,
		Name:     &g.Name,
		RuleType: &g.RuleType,
		Action:   &g.Action,
		Pattern:  &g.Pattern,
		Priority: &g.Priority,
		Enabled:  &enabled,
	}
	return errOf(client.CliAiFirewallGuardrail(env, req))
}

// applyKey resolves the key from the source the file names. The file itself
// never holds the key.
func applyKey(client *vdb.Client, env vdb.CliEnv, c aifw.Change) error {
	src := c.Provider.Key
	var key string
	switch {
	case src.FromEnv != "":
		key = os.Getenv(src.FromEnv)
		if key == "" {
			return fmt.Errorf("$%s is not set", src.FromEnv)
		}
	case src.FromFile != "":
		data, err := os.ReadFile(expandHome(src.FromFile))
		if err != nil {
			return err
		}
		key = strings.TrimSpace(string(data))
	}
	if key == "" {
		return fmt.Errorf("the key is empty")
	}
	return errOf(client.CliAiFirewallKey(env, vdb.CliAiFirewallKeyRequest{
		Provider: c.Provider.Slug, APIKey: key,
	}))
}

func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

func providerAction(action string) string {
	if action == "default" {
		return "clear"
	}
	return action
}

func errOf[T any](_ *vdb.CliResponse[T], err error) error { return err }

func renderAiFirewallPlan(ctx *display.Context, path, baselineNote string, changes []aifw.Change, dryRun bool) string {
	t := ctx.Term
	var b strings.Builder

	title := "AI Firewall policy applied"
	if dryRun {
		title = "AI Firewall policy plan (dry run — nothing was changed)"
	}
	b.WriteString(display.Bold(t, title) + "\n")
	kv := []display.KVPair{{Key: "Policy file", Value: path}}
	if baselineNote != "" {
		kv = append(kv, display.KVPair{Key: "Baseline", Value: baselineNote})
	}
	b.WriteString(display.KeyValue(t, kv) + "\n")

	mutating := aifw.Mutating(changes)
	b.WriteString("\n" + display.Subheader(t, "Changes") + "\n")
	if len(mutating) == 0 {
		b.WriteString("  The org's policy already matches this file.\n")
	} else {
		cols := []display.Column{
			{Header: "Op"}, {Header: "Kind"}, {Header: "Target"}, {Header: "Detail"},
		}
		rows := make([][]string, 0, len(mutating))
		for _, c := range mutating {
			rows = append(rows, []string{string(c.Op), string(c.Kind), c.Target, c.Detail})
		}
		b.WriteString(display.Table(t, cols, rows))
	}

	// Drift is reported, never silently destroyed.
	var drift []aifw.Change
	for _, c := range changes {
		if c.Op == aifw.OpDrift {
			drift = append(drift, c)
		}
	}
	if len(drift) > 0 {
		b.WriteString("\n" + display.Subheader(t, "Drift (left alone)") + "\n")
		for _, c := range drift {
			b.WriteString(fmt.Sprintf("  %s %q: %s\n", c.Kind, c.Target, c.Detail))
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

// --- export ---

func newAiFirewallExportCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Write the org's current policy to a policy file",
		Long: `Serialise the org's live AI Firewall policy into .vulnetix/ai-firewall.yaml, so
it can be reviewed, committed, and re-applied.

Provider keys are never written: the server does not return them.`,
		Args: cobra.NoArgs,
		RunE: runAiFirewallExport,
	}
	cmd.Flags().StringP("file", "f", aifw.DefaultPolicyPath, "Where to write the policy")
	cmd.Flags().Bool("stdout", false, "Write to stdout instead of a file")
	cmd.Flags().Bool("force", false, "Overwrite an existing file")
	addAiFirewallCommonFlags(cmd)
	return cmd
}

func runAiFirewallExport(cmd *cobra.Command, args []string) error {
	if err := initAiFirewallOutput(cmd); err != nil {
		return err
	}
	ctx := display.FromCommand(cmd)

	orgID, _, _, err := packageFirewallAPIKey(flagString(cmd, "base-url"))
	if err != nil {
		return err
	}
	client, err := newPackageFirewallConfigClient(cmd)
	if err != nil {
		return err
	}
	resp, err := client.CliAiFirewallState(envForCli())
	if err != nil {
		return err
	}

	var catalog []string
	for _, p := range resp.Data.Providers {
		catalog = append(catalog, p.Slug)
	}
	body, err := aifw.Export(orgID, serverStateFrom(resp.Data), catalog)
	if err != nil {
		return err
	}

	toStdout, _ := cmd.Flags().GetBool("stdout")
	if toStdout {
		ctx.Logger.Result(string(body))
		return nil
	}

	path, _ := cmd.Flags().GetString("file")
	force, _ := cmd.Flags().GetBool("force")
	if _, err := os.Stat(path); err == nil && !force {
		return fmt.Errorf("%s already exists; pass --force to overwrite", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(path, body, 0644); err != nil {
		return err
	}

	if ctx.IsJSON() {
		return ctx.Logger.ResultJSON(map[string]any{"path": path})
	}
	ctx.Logger.Result("Wrote " + path + "\n\nReview it, then apply with:\n  vulnetix ai-firewall apply -f " + path + " --dry-run")
	return nil
}

// --- snippet ---

func newAiFirewallSnippetCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "snippet",
		Short: "Print ready-to-run code wired to the gateway",
		Long: `Emit boilerplate that calls the gateway, with the base URL and key already
wired for this org.

This is the only way to route some clients through the firewall. The Vercel AI
SDK ignores OPENAI_BASE_URL, and most providers (Mistral, xAI, OpenRouter,
Together, Fireworks, DeepSeek) have no base-URL environment variable that any SDK
reads — for those, setting base_url in code is not a convenience, it is the
mechanism.

Writes to stdout by default, so it pipes.`,
		Args: cobra.NoArgs,
		RunE: runAiFirewallSnippet,
	}
	cmd.Flags().String("lang", "python", "Language: "+strings.Join(aifw.SnippetLangs(), ", "))
	cmd.Flags().String("sdk", "openai", "SDK: "+strings.Join(aifw.SnippetSDKs(), ", "))
	cmd.Flags().String("provider", "", "Provider slug (default: the first with a stored key)")
	cmd.Flags().String("model", "", "Model to call (default: one this org allows)")
	cmd.Flags().String("output-file", "", "Write to this file instead of stdout")
	cmd.Flags().Bool("force", false, "Overwrite an existing output file")
	addAiFirewallWiringFlags(cmd)
	_ = cmd.RegisterFlagCompletionFunc("lang", cobra.FixedCompletions(aifw.SnippetLangs(), cobra.ShellCompDirectiveNoFileComp))
	_ = cmd.RegisterFlagCompletionFunc("sdk", cobra.FixedCompletions(aifw.SnippetSDKs(), cobra.ShellCompDirectiveNoFileComp))
	return cmd
}

func runAiFirewallSnippet(cmd *cobra.Command, args []string) error {
	if err := initAiFirewallOutput(cmd); err != nil {
		return err
	}
	ctx := display.FromCommand(cmd)

	lang, _ := cmd.Flags().GetString("lang")
	sdk, _ := cmd.Flags().GetString("sdk")
	snip, err := aifw.FindSnippet(lang, sdk)
	if err != nil {
		return err
	}

	fwctx, err := loadAiFirewallContext(cmd)
	if err != nil {
		return err
	}

	provider, _ := cmd.Flags().GetString("provider")
	if snip.Provider != "" {
		provider = snip.Provider
	}
	if provider == "" {
		provider = firstProviderWithKey(fwctx)
	}
	if provider == "" {
		return fmt.Errorf("no provider has a stored key — run 'vulnetix ai-firewall key set <provider>' first")
	}
	p, ok := aifw.ProviderBySlug(provider)
	if !ok {
		return fmt.Errorf("unknown provider %q", provider)
	}
	// An OpenAI-shaped snippet aimed at Anthropic (or vice versa) would be built
	// from the wrong base URL and 404 on the first call. Refuse rather than emit
	// code that cannot work.
	if !snip.Supports(p) {
		return fmt.Errorf("the %s/%s snippet speaks a wire %s does not serve — use --sdk anthropic for %s, or pick an OpenAI-compatible provider",
			lang, sdk, provider, provider)
	}

	model, _ := cmd.Flags().GetString("model")
	if model == "" {
		model = defaultModelFor(fwctx, provider)
	}
	if ok, reason := fwctx.Policy.ModelAllowed(provider, model); !ok {
		return fmt.Errorf("model %q would be refused for %s (%s) — pick one this org allows", model, provider, reason)
	}

	body, err := aifw.RenderSnippet(snip, aifw.SnippetData{
		GatewayURL: fwctx.Options.BaseURL(provider),
		Provider:   provider,
		OrgUUID:    fwctx.Options.OrgUUID,
		Model:      model,
		KeyEnv:     aifw.VulnetixKeyEnv,
	})
	if err != nil {
		return err
	}

	outPath, _ := cmd.Flags().GetString("output-file")
	if outPath == "" {
		if ctx.IsJSON() {
			return ctx.Logger.ResultJSON(map[string]any{"content": body})
		}
		ctx.Logger.Result(body)
		return nil
	}

	force, _ := cmd.Flags().GetBool("force")
	if _, err := os.Stat(outPath); err == nil && !force {
		return fmt.Errorf("%s already exists; pass --force to overwrite", outPath)
	}
	if dir := filepath.Dir(outPath); dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}
	if err := os.WriteFile(outPath, []byte(body), 0644); err != nil {
		return err
	}
	if ctx.IsJSON() {
		return ctx.Logger.ResultJSON(map[string]any{"path": outPath, "content": body})
	}
	ctx.Logger.Result("Wrote " + outPath)
	return nil
}

func firstProviderWithKey(fwctx *aiFirewallContext) string {
	for _, p := range fwctx.State.Providers {
		if p.HasKey {
			return p.Slug
		}
	}
	return ""
}

// defaultModelFor picks a model the org allows. In allowlist mode that is one of
// the allowed entries; otherwise there is nothing to go on, so the caller must
// pass --model.
func defaultModelFor(fwctx *aiFirewallContext, provider string) string {
	for _, m := range fwctx.State.ModelPolicies {
		if m.ProviderSlug == provider && m.Action == "allow" {
			return m.Slug
		}
	}
	switch provider {
	case "anthropic":
		return "claude-sonnet-4-5"
	default:
		return "gpt-4o"
	}
}
