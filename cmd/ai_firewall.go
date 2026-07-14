package cmd

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/managedfile"
	aifw "github.com/vulnetix/cli/v3/pkg/aifirewall"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// The AI Firewall (guardrails.vulnetix.com) is an OpenAI-compatible gateway that
// enforces the org's provider, model, and guardrail policy inline. These
// commands wire local AI clients to it, prove they are wired, and manage the
// policy it enforces. Separate from the Package Firewall, which proxies package
// registries.

type aiFirewallAction struct {
	Target string
	Result string
}

func newAiFirewallCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ai-firewall",
		Short: "Wire AI clients to the Vulnetix AI Firewall and manage its policy",
		Long: `Manage the Vulnetix AI Firewall for the authenticated organisation.

The firewall is a hosted OpenAI-compatible gateway:

    https://guardrails.vulnetix.com/{providerSlug}/{orgUuid}/v1

A client points its base URL there and authenticates with the Vulnetix API key.
The org's own provider key never leaves the server: the gateway applies the
provider, model, and guardrail policy, then swaps in the provider key and
forwards the request upstream.

    install     wire the AI clients on this machine to the gateway
    status      show what is wired, and where local config conflicts with policy
    policy      provider / model / guardrail rules the gateway enforces
    key         store this org's provider API keys (BYOK)
    apply       reconcile the org's policy from .vulnetix/ai-firewall.yaml
    snippet     print ready-to-run code wired to the gateway`,
	}
	cmd.AddCommand(newAiFirewallStatusCommand())
	cmd.AddCommand(newAiFirewallInstallCommand())
	cmd.AddCommand(newAiFirewallUninstallCommand())
	cmd.AddCommand(newAiFirewallPolicyCommand())
	cmd.AddCommand(newAiFirewallKeyCommand())
	cmd.AddCommand(newAiFirewallSettingsCommand())
	cmd.AddCommand(newAiFirewallGetCommand())
	cmd.AddCommand(newAiFirewallSnippetCommand())
	cmd.AddCommand(newAiFirewallBaselineCommand())
	cmd.AddCommand(newAiFirewallApplyCommand())
	cmd.AddCommand(newAiFirewallExportCommand())
	return cmd
}

func init() {
	rootCmd.AddCommand(newAiFirewallCommand())
}

// addAiFirewallWiringFlags are the flags every command that touches the gateway
// URL or local files needs.
func addAiFirewallWiringFlags(cmd *cobra.Command) {
	cmd.Flags().String("base-url", vdb.DefaultBaseURL, "VDB API base URL")
	cmd.Flags().String("gateway-url", aifw.DefaultGatewayURL, "AI Firewall gateway URL")
	cmd.Flags().StringP("output", "o", "pretty", "Output format (pretty, json)")
	_ = cmd.RegisterFlagCompletionFunc("output", cobra.FixedCompletions([]string{"pretty", "json"}, cobra.ShellCompDirectiveNoFileComp))
}

// aiFirewallContext gathers everything a wiring command needs: the org's policy
// from the server, and the local paths to write.
type aiFirewallContext struct {
	Options aifw.Options
	State   vdb.CliAiFirewallState
	Gateway *aifw.Gateway
	Host    string
	Policy  aifw.Policy
	Source  string // credential source, for the output header
}

func loadAiFirewallContext(cmd *cobra.Command) (*aiFirewallContext, error) {
	baseURL, _ := cmd.Flags().GetString("base-url")
	gatewayURL, _ := cmd.Flags().GetString("gateway-url")

	orgID, apiKey, source, err := packageFirewallAPIKey(baseURL)
	if err != nil {
		return nil, err
	}
	host, err := aifw.GatewayHost(gatewayURL)
	if err != nil {
		return nil, err
	}

	client, err := newPackageFirewallConfigClient(cmd)
	if err != nil {
		return nil, err
	}
	resp, err := client.CliAiFirewallState(envForCli())
	if err != nil {
		return nil, err
	}
	state := resp.Data

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	root, _ := managedfile.GitRoot() // "" outside a repository is fine

	var gw *aifw.Gateway
	if state.Gateway != nil {
		gw = &aifw.Gateway{BaseURL: state.Gateway.BaseURL, WireAPIs: state.Gateway.WireAPIs}
	}

	ctx := &aiFirewallContext{
		Options: aifw.Options{
			Gateway: gatewayURL,
			OrgUUID: orgID,
			APIKey:  apiKey,
			Home:    home,
			Root:    root,
		},
		State:   state,
		Gateway: gw,
		Host:    host,
		Policy:  buildPolicy(state, gw),
		Source:  source,
	}
	return ctx, nil
}

func buildPolicy(state vdb.CliAiFirewallState, gw *aifw.Gateway) aifw.Policy {
	pol := aifw.Policy{
		ProviderAction: map[string]string{},
		ProviderHasKey: map[string]bool{},
		ModelAction:    map[string]string{},
		AllowlistMode:  map[string]bool{},
		Gateway:        gw,
	}
	for _, p := range state.Providers {
		pol.ProviderAction[p.Slug] = p.OrgAction
		pol.ProviderHasKey[p.Slug] = p.HasKey
	}
	for _, m := range state.ModelPolicies {
		pol.ModelAction[m.ProviderSlug+"/"+m.Slug] = m.Action
		if m.Action == "allow" {
			pol.AllowlistMode[m.ProviderSlug] = true
		}
	}
	for _, g := range state.Guardrails {
		pol.Guardrails = append(pol.Guardrails, aifw.Guardrail{
			Name: g.Name, RuleType: g.RuleType, Pattern: g.Pattern,
			Enabled: g.Enabled, Priority: g.Priority,
		})
	}
	return pol
}

// resolveTargets picks the providers to wire: those named with --provider, or
// every provider the org holds a key for. A provider with no key is never wired
// — the gateway would refuse every request with provider_key_missing, so writing
// the config would only produce a confusing failure later.
func (c *aiFirewallContext) resolveTargets(named []string) ([]aifw.Provider, []string, error) {
	var targets []aifw.Provider
	var skipped []string

	want := map[string]bool{}
	for _, n := range named {
		slug := strings.TrimSpace(n)
		if _, ok := aifw.ProviderBySlug(slug); !ok {
			return nil, nil, fmt.Errorf("unknown provider %q", slug)
		}
		want[slug] = true
	}

	for _, p := range aifw.Providers() {
		if len(want) > 0 && !want[p.Slug] {
			continue
		}
		hasKey, known := c.Policy.ProviderHasKey[p.Slug]
		if !known {
			if len(want) > 0 {
				return nil, nil, fmt.Errorf("provider %q is not in the gateway catalog", p.Slug)
			}
			continue
		}
		if !hasKey {
			if len(want) > 0 {
				skipped = append(skipped, fmt.Sprintf("%s: no key stored for this org — run 'vulnetix ai-firewall key set %s'", p.Slug, p.Slug))
			}
			continue
		}
		if c.Policy.ProviderAction[p.Slug] == "deny" {
			skipped = append(skipped, fmt.Sprintf("%s: denied by org policy", p.Slug))
			continue
		}
		targets = append(targets, p)
	}
	return targets, skipped, nil
}

// --- status ---

func newAiFirewallStatusCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show what is wired to the gateway, and where it conflicts with policy",
		Long: `Report the org's AI Firewall policy, which local AI clients are wired to the
gateway, and every way the two disagree.

The checks catch the failures you would otherwise meet as an unexplained 403 at
request time — a pinned model the org denies, a provider with no stored key — and
the quieter one that never errors at all: a client whose base URL points
somewhere other than the gateway, whose traffic is therefore not screened.

Exits 0 even when checks fail, so it is safe in a shell prompt. Use --strict to
exit non-zero on any error-level finding (for CI).`,
		Args: cobra.NoArgs,
		RunE: runAiFirewallStatus,
	}
	cmd.Flags().Bool("strict", false, "Exit 2 if any error-level check fails")
	addAiFirewallWiringFlags(cmd)
	return cmd
}

func runAiFirewallStatus(cmd *cobra.Command, args []string) error {
	if err := initAiFirewallOutput(cmd); err != nil {
		return err
	}
	fwctx, err := loadAiFirewallContext(cmd)
	if err != nil {
		return err
	}
	ctx := display.FromCommand(cmd)

	// Detect against every provider, not just the wired targets: the point is to
	// find clients pointing somewhere unexpected.
	fwctx.Options.Targets = aifw.Providers()
	detected := aifw.Detect(fwctx.Options, fwctx.Host)
	checks := aifw.RunChecks(fwctx.Policy, detected, fwctx.Host)

	strict, _ := cmd.Flags().GetBool("strict")
	errCount := aifw.Errors(checks)

	if ctx.IsJSON() {
		if err := ctx.Logger.ResultJSON(map[string]any{
			"gateway": map[string]any{
				"baseUrl":     fwctx.Options.Gateway,
				"org":         fwctx.Options.OrgUUID,
				"logsEnabled": fwctx.State.LogsEnabled,
			},
			"providers":  fwctx.State.Providers,
			"guardrails": fwctx.State.Guardrails,
			"clients":    jsonClients(detected),
			"checks":     checks,
			"summary": map[string]int{
				"errors":   errCount,
				"warnings": aifw.Warnings(checks),
			},
		}); err != nil {
			return err
		}
	} else {
		ctx.Logger.Result(renderAiFirewallStatus(ctx, fwctx, detected, checks))
	}

	if strict && errCount > 0 {
		return fmt.Errorf("%d error-level check(s) failed", errCount)
	}
	return nil
}

func isWindows() bool { return runtime.GOOS == "windows" }

func jsonClients(detected []aifw.Detected) []map[string]any {
	out := make([]map[string]any, 0, len(detected))
	for _, d := range detected {
		out = append(out, map[string]any{
			"id":      d.Client.ID,
			"name":    d.Client.DisplayName,
			"scope":   string(d.Scope),
			"path":    d.Path,
			"state":   string(d.State),
			"baseUrl": d.BaseURL,
			"model":   d.Model,
		})
	}
	return out
}

func renderAiFirewallStatus(ctx *display.Context, fwctx *aiFirewallContext, detected []aifw.Detected, checks []aifw.Check) string {
	t := ctx.Term
	var b strings.Builder

	b.WriteString(display.Bold(t, "Vulnetix AI Firewall") + "\n")
	b.WriteString(display.KeyValue(t, []display.KVPair{
		{Key: "Gateway", Value: fwctx.Options.Gateway},
		{Key: "Organization", Value: fwctx.Options.OrgUUID},
		{Key: "Credential source", Value: fwctx.Source},
		{Key: "Inference logging", Value: onOff(fwctx.State.LogsEnabled)},
	}) + "\n")

	b.WriteString("\n" + display.Subheader(t, "Providers") + "\n")
	if len(fwctx.State.Providers) == 0 {
		b.WriteString("  No providers in the catalog.\n")
	} else {
		cols := []display.Column{
			{Header: "Slug"}, {Header: "Org policy"}, {Header: "Key"}, {Header: "Wiring"},
		}
		rows := make([][]string, 0, len(fwctx.State.Providers))
		for _, p := range fwctx.State.Providers {
			action := p.OrgAction
			if action == "" {
				action = "default (allow)"
			}
			key := "missing"
			if p.HasKey {
				key = "stored"
			}
			wiring := "snippet only (no SDK base-URL env var)"
			if lp, ok := aifw.ProviderBySlug(p.Slug); ok && lp.EnvWired() {
				wiring = strings.Join(lp.BaseURLEnv, ", ")
			}
			rows = append(rows, []string{p.Slug, action, key, wiring})
		}
		b.WriteString(display.Table(t, cols, rows))
	}

	b.WriteString("\n" + display.Subheader(t, "Guardrails") + "\n")
	if len(fwctx.State.Guardrails) == 0 {
		b.WriteString("  No guardrails configured.\n")
	} else {
		cols := []display.Column{
			{Header: "Priority", Align: display.AlignRight}, {Header: "Name"},
			{Header: "Rule"}, {Header: "Action"}, {Header: "Enabled"},
		}
		rows := make([][]string, 0, len(fwctx.State.Guardrails))
		for _, g := range fwctx.State.Guardrails {
			rows = append(rows, []string{
				fmt.Sprint(g.Priority), g.Name, g.RuleType, g.Action, fmt.Sprint(g.Enabled),
			})
		}
		b.WriteString(display.Table(t, cols, rows))
	}

	b.WriteString("\n" + display.Subheader(t, "Local clients") + "\n")
	cols := []display.Column{
		{Header: "Client"}, {Header: "Scope"}, {Header: "State"}, {Header: "Path"},
	}
	rows := make([][]string, 0, len(detected))
	for _, d := range detected {
		if d.State == aifw.StateAbsent {
			continue
		}
		rows = append(rows, []string{d.Client.DisplayName, string(d.Scope), string(d.State), d.Path})
	}
	if len(rows) == 0 {
		b.WriteString("  No AI clients detected on this machine.\n")
	} else {
		b.WriteString(display.Table(t, cols, rows))
	}

	b.WriteString("\n" + display.Subheader(t, "Checks") + "\n")
	if len(checks) == 0 {
		b.WriteString("  No problems found.\n")
		return strings.TrimRight(b.String(), "\n")
	}
	for _, c := range checks {
		label := "warning"
		if c.Severity == aifw.SeverityError {
			label = "error"
		}
		b.WriteString(fmt.Sprintf("  [%s] %s\n", label, c.Message))
	}
	return strings.TrimRight(b.String(), "\n")
}

func onOff(v bool) string {
	if v {
		return "on"
	}
	return "off"
}

// --- install ---

func newAiFirewallInstallCommand() *cobra.Command {
	ids := clientIDs()
	cmd := &cobra.Command{
		Use:   "install [client...]",
		Short: "Wire the AI clients on this machine to the gateway",
		Long: `Point local AI clients at the gateway, so their requests are screened by the
org's policy.

With no arguments, every client detected on this machine is wired. Name one or
more to wire exactly those: ` + strings.Join(ids, ", ") + `.

Only providers the org holds a key for are wired — without one the gateway
refuses every request with provider_key_missing, so a config pointing at it would
only fail later.

The Vulnetix API key is referenced ($` + aifw.VulnetixKeyEnv + `), never written
into a config file, unless you pass --embed-key.`,
		RunE: runAiFirewallInstall,
	}
	cmd.Flags().StringSlice("provider", nil, "Providers to wire (default: every provider with a stored key)")
	cmd.Flags().String("model", "", "Default model to pin in agent configs")
	cmd.Flags().String("scope", "", "Where to write config: user or project")
	cmd.Flags().Bool("embed-key", false, "Write the literal API key instead of referencing $"+aifw.VulnetixKeyEnv)
	cmd.Flags().Bool("create-env", false, "Create a project .env if none exists")
	cmd.Flags().Bool("dry-run", false, "Show planned changes without writing files")
	addAiFirewallWiringFlags(cmd)
	_ = cmd.RegisterFlagCompletionFunc("scope", cobra.FixedCompletions([]string{"user", "project"}, cobra.ShellCompDirectiveNoFileComp))
	cmd.ValidArgs = ids
	return cmd
}

func clientIDs() []string {
	var ids []string
	for _, c := range aifw.Clients() {
		ids = append(ids, c.ID)
	}
	sort.Strings(ids)
	return ids
}

func runAiFirewallInstall(cmd *cobra.Command, args []string) error {
	if err := initAiFirewallOutput(cmd); err != nil {
		return err
	}
	fwctx, err := loadAiFirewallContext(cmd)
	if err != nil {
		return err
	}
	ctx := display.FromCommand(cmd)

	named, _ := cmd.Flags().GetStringSlice("provider")
	targets, skipped, err := fwctx.resolveTargets(named)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("no provider is ready to wire: store a provider key first with 'vulnetix ai-firewall key set <provider>'")
	}

	model, _ := cmd.Flags().GetString("model")
	scope, _ := cmd.Flags().GetString("scope")
	embed, _ := cmd.Flags().GetBool("embed-key")
	createEnv, _ := cmd.Flags().GetBool("create-env")
	dryRun, _ := cmd.Flags().GetBool("dry-run")

	if scope != "" && scope != string(aifw.ScopeUser) && scope != string(aifw.ScopeProject) {
		return fmt.Errorf("--scope must be one of: user, project")
	}
	if err := validateModel(fwctx, targets, model); err != nil {
		return err
	}

	o := fwctx.Options
	o.Targets = targets
	o.Model = model
	o.EmbedKey = embed
	o.Scope = aifw.Scope(scope)

	clients, err := resolveInstallClients(args, o)
	if err != nil {
		return err
	}

	var actions []aiFirewallAction
	var manual []aifw.Client
	for _, c := range clients {
		if c.Manual {
			manual = append(manual, c)
			continue
		}
		got, err := installClient(c, o, fwctx, createEnv, dryRun)
		if err != nil {
			return err
		}
		actions = append(actions, got...)
	}

	if ctx.IsJSON() {
		return ctx.Logger.ResultJSON(map[string]any{
			"dryRun":   dryRun,
			"org":      o.OrgUUID,
			"gateway":  o.Gateway,
			"targets":  providerSlugs(targets),
			"skipped":  skipped,
			"actions":  jsonActions(actions),
			"manual":   manualInstructions(manual, o),
			"embedKey": embed,
		})
	}
	ctx.Logger.Result(renderAiFirewallInstall(ctx, o, fwctx, targets, skipped, actions, manual, dryRun))
	return nil
}

// validateModel refuses to pin a model the gateway will reject. Writing it and
// letting the user discover the 403 at request time would be a worse experience
// than failing here, where the reason is obvious.
func validateModel(fwctx *aiFirewallContext, targets []aifw.Provider, model string) error {
	if model == "" {
		return nil
	}
	for _, p := range targets {
		if ok, reason := fwctx.Policy.ModelAllowed(p.Slug, model); !ok {
			return fmt.Errorf("model %q would be refused for %s (%s) — pick a model this org allows, or change the policy with 'vulnetix ai-firewall policy model'", model, p.Slug, reason)
		}
	}
	return nil
}

// resolveInstallClients returns the clients to wire: those named, or every one
// detected on this machine.
func resolveInstallClients(args []string, o aifw.Options) ([]aifw.Client, error) {
	if len(args) > 0 {
		var out []aifw.Client
		for _, name := range args {
			c, ok := aifw.ClientByID(strings.TrimSpace(name))
			if !ok {
				return nil, fmt.Errorf("unknown client %q (known: %s)", name, strings.Join(clientIDs(), ", "))
			}
			out = append(out, c)
		}
		return out, nil
	}
	var out []aifw.Client
	for _, c := range aifw.Clients() {
		if aifw.Installed(c, o.ScopeOrDefault(c.DefaultScope), o.Home, o.Root) {
			out = append(out, c)
		}
	}
	return out, nil
}

func installClient(c aifw.Client, o aifw.Options, fwctx *aiFirewallContext, createEnv, dryRun bool) ([]aiFirewallAction, error) {
	// A client that speaks a wire the gateway does not proxy for its provider
	// cannot be wired at all. Say so; do not write a config that 404s.
	if provider := clientProviderSlug(c); provider != "" {
		if ok, why := aifw.SupportsWire(fwctx.Gateway, c, provider); !ok {
			return []aiFirewallAction{{Target: c.DisplayName, Result: "skipped — " + why}}, nil
		}
		if !o.HasTarget(provider) {
			return []aiFirewallAction{{Target: c.DisplayName, Result: "skipped — no key stored for " + provider}}, nil
		}
	}

	switch c.ID {
	case "shell":
		return installShell(o, dryRun)
	case "env":
		return installProjectEnv(o, createEnv, dryRun)
	case "claude-code":
		return installFiles(o, dryRun, fileOf(aifw.ClaudeCodeFile(o)), fileOf(aifw.ClaudeCodeSecretsFile(o)))
	case "codex":
		return installFiles(o, dryRun, fileOf(aifw.CodexFile(o)))
	case "continue":
		files := []*managedfile.File{fileOf(aifw.ContinueFile(o))}
		// Continue runs in an IDE and cannot read the shell environment, so the key
		// must be written to ~/.continue/.env for ${{ secrets.X }} to resolve. This
		// is the one place the credential is unavoidably a literal.
		if f, ok := aifw.ContinueSecretsFile(o); ok {
			files = append(files, &f)
		}
		return installFiles(o, dryRun, files...)
	case "aider":
		return installFiles(o, dryRun, fileOf(aifw.AiderFile(o)))
	}
	return nil, nil
}

func fileOf(f managedfile.File, ok bool) *managedfile.File {
	if !ok {
		return nil
	}
	return &f
}

func installShell(o aifw.Options, dryRun bool) ([]aiFirewallAction, error) {
	vars := aifw.EnvVars(o, "shell")
	if len(vars) == 0 {
		return nil, nil
	}
	if isWindows() {
		if dryRun {
			return []aiFirewallAction{{Target: "Windows user environment", Result: fmt.Sprintf("would set %d variable(s)", len(vars))}}, nil
		}
		if err := managedfile.PersistUserEnv(vars); err != nil {
			return nil, err
		}
		return []aiFirewallAction{{Target: "Windows user environment", Result: fmt.Sprintf("set %d variable(s)", len(vars))}}, nil
	}

	path, block, err := aifw.ShellFile(o)
	if err != nil {
		return nil, err
	}
	changed, err := managedfile.UpsertBlockFile(path, block, aifw.Markers, dryRun)
	if err != nil {
		return nil, err
	}
	return []aiFirewallAction{{Target: path, Result: blockResult(changed, dryRun)}}, nil
}

func blockResult(changed, dryRun bool) string {
	switch {
	case !changed:
		return "already configured"
	case dryRun:
		return "would update shell config"
	default:
		return "updated shell config (restart your shell, or source the file)"
	}
}

func installProjectEnv(o aifw.Options, createEnv, dryRun bool) ([]aiFirewallAction, error) {
	if o.Root == "" {
		return []aiFirewallAction{{Target: "project env", Result: "skipped — not in a git repository"}}, nil
	}
	files := aifw.ProjectEnvFiles(o)
	if len(files) == 0 {
		if !createEnv {
			// An invented .env would not be loaded by anything the project already
			// runs, so silently creating one would be theatre.
			return []aiFirewallAction{{
				Target: o.Root,
				Result: "no .env, .envrc, or Makefile found — pass --create-env to create a .env",
			}}, nil
		}
		files = []managedfile.File{aifw.CreateProjectEnv(o)}
	}
	return installFiles(o, dryRun, filePtrs(files)...)
}

func filePtrs(files []managedfile.File) []*managedfile.File {
	out := make([]*managedfile.File, 0, len(files))
	for i := range files {
		out = append(out, &files[i])
	}
	return out
}

func installFiles(o aifw.Options, dryRun bool, files ...*managedfile.File) ([]aiFirewallAction, error) {
	var actions []aiFirewallAction
	for _, f := range files {
		if f == nil || f.Path == "" {
			continue
		}
		// A file that will hold a literal credential must not be one that git will
		// happily commit.
		if o.EmbedKey && isSecretFile(*f, o) {
			if err := aifw.SecretSafe(f.Path); err != nil {
				return nil, err
			}
		}
		out, err := managedfile.UpsertFile(*f, aifw.Markers, dryRun)
		if err != nil {
			return nil, err
		}
		if !dryRun && out.Changed && isSecretFile(*f, o) {
			if err := aifw.Chmod600(f.Path); err != nil {
				return nil, err
			}
		}
		actions = append(actions, aiFirewallAction{Target: f.Path, Result: writeResult(out, dryRun)})
	}
	return actions, nil
}

// isSecretFile reports whether a file holds the API key in the clear.
func isSecretFile(f managedfile.File, o aifw.Options) bool {
	if strings.HasSuffix(f.Path, ".continue/.env") || strings.HasSuffix(f.Path, "settings.local.json") {
		return true
	}
	return o.EmbedKey && strings.Contains(f.Content, o.APIKey) && o.APIKey != ""
}

func writeResult(out managedfile.WriteOutcome, dryRun bool) string {
	switch {
	case !out.Changed:
		return "already configured"
	case dryRun && out.BackedUp:
		return "would update config (backing up the existing file)"
	case dryRun:
		return "would update config"
	case out.BackedUp:
		return "updated config (backup written)"
	default:
		return "updated config"
	}
}

func renderAiFirewallInstall(ctx *display.Context, o aifw.Options, fwctx *aiFirewallContext, targets []aifw.Provider, skipped []string, actions []aiFirewallAction, manual []aifw.Client, dryRun bool) string {
	t := ctx.Term
	var b strings.Builder

	if dryRun {
		b.WriteString(display.Bold(t, "Vulnetix AI Firewall install dry run") + "\n")
	} else {
		b.WriteString(display.Bold(t, "Vulnetix AI Firewall install complete") + "\n")
	}
	b.WriteString(display.KeyValue(t, []display.KVPair{
		{Key: "Credential source", Value: fwctx.Source},
		{Key: "Organization", Value: o.OrgUUID},
		{Key: "Gateway", Value: o.Gateway},
		{Key: "Providers", Value: strings.Join(providerSlugs(targets), ", ")},
		{Key: "API key", Value: managedfile.MaskSecret(o.APIKey)},
	}) + "\n")

	b.WriteString("\n" + display.Subheader(t, "Actions") + "\n")
	if len(actions) == 0 {
		b.WriteString("  Nothing to do.\n")
	}
	for _, a := range actions {
		b.WriteString(fmt.Sprintf("  %s: %s\n", a.Target, a.Result))
	}

	if len(skipped) > 0 {
		b.WriteString("\n" + display.Subheader(t, "Skipped providers") + "\n")
		for _, s := range skipped {
			b.WriteString("  " + s + "\n")
		}
	}

	// Providers no SDK can be pointed at with an environment variable. Saying
	// nothing here would let the user assume the shell block covered them.
	var snippetOnly []string
	for _, p := range targets {
		if !p.EnvWired() {
			snippetOnly = append(snippetOnly, p.Slug)
		}
	}
	if len(snippetOnly) > 0 {
		b.WriteString("\n" + display.Subheader(t, "Not reachable by environment variable") + "\n")
		b.WriteString("  No SDK reads a base-URL variable for: " + strings.Join(snippetOnly, ", ") + "\n")
		b.WriteString("  Set base_url in code instead:\n")
		b.WriteString(fmt.Sprintf("    vulnetix ai-firewall snippet --provider %s --lang python --sdk openai\n", snippetOnly[0]))
	}

	if len(manual) > 0 {
		b.WriteString("\n" + display.Subheader(t, "Configure by hand") + "\n")
		for _, line := range manualInstructions(manual, o) {
			b.WriteString("  " + line + "\n")
		}
	}

	if !dryRun {
		b.WriteString("\n  Verify with: vulnetix ai-firewall status\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// manualInstructions covers the clients that keep the base URL in application
// state rather than a config file. There is nothing to write, so the honest
// thing is to say exactly what to paste and where.
func manualInstructions(manual []aifw.Client, o aifw.Options) []string {
	var out []string
	for _, c := range manual {
		slug := clientProviderSlug(c)
		if slug == "" {
			slug = "openai"
		}
		url := o.BaseURL(slug)
		switch c.ID {
		case "cursor":
			out = append(out,
				"Cursor — Settings > Models > Override OpenAI Base URL:",
				"    Base URL: "+url,
				"    API key:  your $"+aifw.VulnetixKeyEnv,
				"    (Cursor stores this in application state; there is no file to write.)",
				"    Its integrated terminal inherits the shell block, so aider/codex run inside it are already wired.",
			)
		case "windsurf":
			out = append(out,
				"Windsurf — Settings > Cascade > Model Provider (custom OpenAI endpoint):",
				"    Base URL: "+url,
				"    API key:  your $"+aifw.VulnetixKeyEnv,
				"    (Windsurf stores this in application state; there is no file to write.)",
			)
		}
	}
	return out
}

func clientProviderSlug(c aifw.Client) string {
	if len(c.Providers) == 1 {
		return c.Providers[0]
	}
	return ""
}

func providerSlugs(ps []aifw.Provider) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Slug)
	}
	return out
}

func jsonActions(actions []aiFirewallAction) []map[string]string {
	out := make([]map[string]string, 0, len(actions))
	for _, a := range actions {
		out = append(out, map[string]string{"target": a.Target, "result": a.Result})
	}
	return out
}

// --- uninstall ---

func newAiFirewallUninstallCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "uninstall [client...]",
		Short: "Remove the AI Firewall configuration from local clients",
		Long: `Undo 'vulnetix ai-firewall install'.

Name one or more clients, or use --all, or --except to remove all but the named
ones. Server-side policy (providers, models, guardrails, stored keys) is not
touched — this operates on local files only and needs no authentication.

A config file we merged into is restored from its backup, or has only our keys
stripped from it. A file you wrote is never deleted.`,
		RunE: runAiFirewallUninstall,
	}
	cmd.Flags().Bool("all", false, "Unconfigure every client")
	cmd.Flags().StringSlice("except", nil, "Unconfigure every client except these")
	cmd.Flags().Bool("dry-run", false, "Show planned changes without writing files")
	cmd.Flags().String("gateway-url", aifw.DefaultGatewayURL, "AI Firewall gateway URL (host to detect and strip)")
	cmd.Flags().StringP("output", "o", "pretty", "Output format (pretty, json)")
	_ = cmd.RegisterFlagCompletionFunc("output", cobra.FixedCompletions([]string{"pretty", "json"}, cobra.ShellCompDirectiveNoFileComp))
	cmd.ValidArgs = clientIDs()
	return cmd
}

func runAiFirewallUninstall(cmd *cobra.Command, args []string) error {
	if err := initAiFirewallOutput(cmd); err != nil {
		return err
	}
	ctx := display.FromCommand(cmd)

	all, _ := cmd.Flags().GetBool("all")
	except, _ := cmd.Flags().GetStringSlice("except")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	gatewayURL, _ := cmd.Flags().GetString("gateway-url")

	host, err := aifw.GatewayHost(gatewayURL)
	if err != nil {
		return err
	}
	targets, err := resolveAiFirewallUninstallTargets(args, except, all)
	if err != nil {
		return err
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	root, _ := managedfile.GitRoot()

	// Uninstall needs no server call: it strips what it wrote, for every provider
	// it could have written for.
	o := aifw.Options{
		Gateway: gatewayURL,
		Home:    home,
		Root:    root,
		Targets: aifw.Providers(),
	}

	var actions []aiFirewallAction
	for _, c := range targets {
		got, err := uninstallClient(c, o, host, dryRun)
		if err != nil {
			return err
		}
		actions = append(actions, got...)
	}

	if ctx.IsJSON() {
		return ctx.Logger.ResultJSON(map[string]any{
			"dryRun":  dryRun,
			"clients": clientNames(targets),
			"actions": jsonActions(actions),
		})
	}

	t := ctx.Term
	var b strings.Builder
	if dryRun {
		b.WriteString(display.Bold(t, "Vulnetix AI Firewall uninstall dry run") + "\n")
	} else {
		b.WriteString(display.Bold(t, "Vulnetix AI Firewall uninstall complete") + "\n")
	}
	b.WriteString(display.KeyValue(t, []display.KVPair{
		{Key: "Clients", Value: strings.Join(clientNames(targets), ", ")},
		{Key: "Gateway host", Value: host},
	}) + "\n")
	b.WriteString("\n" + display.Subheader(t, "Actions") + "\n")
	for _, a := range actions {
		b.WriteString(fmt.Sprintf("  %s: %s\n", a.Target, a.Result))
	}
	ctx.Logger.Result(strings.TrimRight(b.String(), "\n"))
	return nil
}

func resolveAiFirewallUninstallTargets(args, except []string, all bool) ([]aifw.Client, error) {
	selectors := 0
	if len(args) > 0 {
		selectors++
	}
	if len(except) > 0 {
		selectors++
	}
	if all {
		selectors++
	}
	if selectors == 0 {
		return nil, fmt.Errorf("select what to remove: name one or more clients, or pass --all or --except")
	}
	if selectors > 1 {
		return nil, fmt.Errorf("use only one selector: client arguments, --all, or --except")
	}

	if all {
		return aifw.Clients(), nil
	}
	if len(except) > 0 {
		skip := map[string]bool{}
		for _, name := range except {
			c, ok := aifw.ClientByID(strings.TrimSpace(name))
			if !ok {
				return nil, fmt.Errorf("unknown client %q", name)
			}
			skip[c.ID] = true
		}
		var out []aifw.Client
		for _, c := range aifw.Clients() {
			if !skip[c.ID] {
				out = append(out, c)
			}
		}
		return out, nil
	}
	var out []aifw.Client
	for _, name := range args {
		c, ok := aifw.ClientByID(strings.TrimSpace(name))
		if !ok {
			return nil, fmt.Errorf("unknown client %q", name)
		}
		out = append(out, c)
	}
	return out, nil
}

func uninstallClient(c aifw.Client, o aifw.Options, host string, dryRun bool) ([]aiFirewallAction, error) {
	if c.Manual {
		return []aiFirewallAction{{
			Target: c.DisplayName,
			Result: "nothing written — clear the base URL override in the application's settings",
		}}, nil
	}

	switch c.ID {
	case "shell":
		if isWindows() {
			if dryRun {
				return []aiFirewallAction{{Target: "Windows user environment", Result: "would clear"}}, nil
			}
			managedfile.ClearUserEnv(aifw.EnvKeys(o))
			return []aiFirewallAction{{Target: "Windows user environment", Result: "cleared"}}, nil
		}
		path, _, err := aifw.ShellFile(o)
		if err != nil {
			return nil, err
		}
		found, err := managedfile.RemoveBlockFile(path, aifw.Markers, dryRun)
		if err != nil {
			return nil, err
		}
		return []aiFirewallAction{{Target: path, Result: removeBlockResult(found, dryRun)}}, nil

	case "env":
		return uninstallFiles(host, dryRun, filePtrs(aifw.ProjectEnvFiles(o))...)
	case "claude-code":
		return uninstallFiles(host, dryRun, fileOf(aifw.ClaudeCodeFile(o)), fileOf(aifw.ClaudeCodeSecretsFile(withEmbed(o))))
	case "codex":
		return uninstallFiles(host, dryRun, fileOf(aifw.CodexFile(o)))
	case "continue":
		files := []*managedfile.File{fileOf(aifw.ContinueFile(o))}
		if f, ok := aifw.ContinueSecretsFile(withEmbed(o)); ok {
			files = append(files, &f)
		}
		return uninstallFiles(host, dryRun, files...)
	case "aider":
		return uninstallFiles(host, dryRun, fileOf(aifw.AiderFile(o)))
	}
	return nil, nil
}

// withEmbed makes the secret-file specs resolvable during uninstall, where there
// is no API key in hand: the path is all that is needed to remove them.
func withEmbed(o aifw.Options) aifw.Options {
	o.EmbedKey = true
	if o.APIKey == "" {
		o.APIKey = "-"
	}
	return o
}

func uninstallFiles(host string, dryRun bool, files ...*managedfile.File) ([]aiFirewallAction, error) {
	var actions []aiFirewallAction
	for _, f := range files {
		if f == nil || f.Path == "" {
			continue
		}
		out, err := managedfile.RemoveFile(*f, aifw.Markers, host, dryRun)
		if err != nil {
			return nil, err
		}
		actions = append(actions, aiFirewallAction{Target: f.Path, Result: removeResult(out, dryRun)})
	}
	return actions, nil
}

func removeBlockResult(found, dryRun bool) string {
	switch {
	case !found:
		return "not configured"
	case dryRun:
		return "would remove managed block"
	default:
		return "removed managed block"
	}
}

func removeResult(out managedfile.RemoveOutcome, dryRun bool) string {
	switch {
	case !out.Configured:
		return "not configured"
	case out.Restored && dryRun:
		return "would restore from backup"
	case out.Restored:
		return "restored from backup"
	case out.Deleted && dryRun:
		return "would delete file"
	case out.Deleted:
		return "deleted file"
	case dryRun:
		return "would remove firewall settings"
	default:
		return "removed firewall settings"
	}
}

func clientNames(cs []aifw.Client) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.ID)
	}
	return out
}
