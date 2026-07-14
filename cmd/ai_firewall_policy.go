package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/managedfile"
	aifw "github.com/vulnetix/cli/v3/pkg/aifirewall"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// The policy subcommands are the same implementation as `config set ai-firewall`
// / `config get ai-firewall`: the constructors in config_ai_firewall.go each
// return a fresh command, so both spellings can be registered from one factory.
// The `config` spelling keeps working — scripts depend on it — but it is not
// marked cobra-deprecated, because that prints a banner on every run and would
// contaminate the stderr of anything parsing `-o json`.

func newAiFirewallPolicyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Provider, model, and guardrail rules the gateway enforces",
		Long: `Configure the org-wide policy the AI Firewall applies to every proxied request.

    provider    allow or deny a provider outright
    model       allow/deny individual models (the first allow entry for a
                provider puts that provider into allowlist-only mode)
    guardrail   content rules: blocked patterns, PII redaction, message caps

Also available as 'vulnetix config set ai-firewall <sub>'.`,
	}
	cmd.AddCommand(newConfigSetAiFirewallProviderCommand())
	cmd.AddCommand(newConfigSetAiFirewallModelCommand())
	cmd.AddCommand(newConfigSetAiFirewallGuardrailCommand())
	return cmd
}

func newAiFirewallGetCommand() *cobra.Command {
	cmd := newConfigGetAiFirewallCommand()
	cmd.Use = "get"
	cmd.Short = "Show the org's providers, model lists, and guardrails"
	return cmd
}

// --- key (BYOK) ---

func newAiFirewallKeyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key",
		Short: "Store this org's provider API keys (BYOK)",
		Long: `Manage the provider API keys the gateway uses upstream.

The key is encrypted server-side under a context bound to this org and provider,
and is never returned by any API — it can only be replaced or removed. Clients
never see it: they authenticate to the gateway with the Vulnetix API key, and the
gateway swaps in the provider key on the way out.

A provider with no stored key refuses every request with 403 provider_key_missing.`,
	}
	cmd.AddCommand(newAiFirewallKeySetCommand())
	cmd.AddCommand(newAiFirewallKeyRemoveCommand())
	return cmd
}

func newAiFirewallKeySetCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set <provider>",
		Short: "Store or replace the provider API key for this org",
		Long: `Store the provider's API key (for example your OpenAI key) for this org.

Read the key from an environment variable (--from-env) or from stdin (--stdin).
--key takes the literal on the command line, which puts your key in the shell
history and in the process list; it warns, and exists only for automation that
has no better option.`,
		Args: cobra.ExactArgs(1),
		RunE: runAiFirewallKeySet,
	}
	cmd.Flags().String("from-env", "", "Read the key from this environment variable")
	cmd.Flags().Bool("stdin", false, "Read the key from stdin")
	cmd.Flags().String("key", "", "The key itself (leaks into shell history — prefer --from-env or --stdin)")
	addAiFirewallCommonFlags(cmd)
	return cmd
}

func runAiFirewallKeySet(cmd *cobra.Command, args []string) error {
	if err := initAiFirewallOutput(cmd); err != nil {
		return err
	}
	slug := strings.TrimSpace(args[0])
	if _, ok := aifw.ProviderBySlug(slug); !ok {
		return fmt.Errorf("unknown provider %q", slug)
	}

	key, err := readProviderKey(cmd)
	if err != nil {
		return err
	}

	client, err := newPackageFirewallConfigClient(cmd)
	if err != nil {
		return err
	}
	ctx := display.FromCommand(cmd)
	resp, err := client.CliAiFirewallKey(envForCli(), vdb.CliAiFirewallKeyRequest{
		Provider: slug,
		APIKey:   key,
	})
	if err != nil {
		return err
	}
	if ctx.IsJSON() {
		return ctx.Logger.ResultJSON(resp.Data)
	}
	ctx.Logger.Result(renderPackageFirewallResult(ctx,
		fmt.Sprintf("Stored %s key (%s)", slug, managedfile.MaskSecret(key)), resp.Data))
	return nil
}

// readProviderKey gets the key from exactly one source and validates it before
// it goes near the wire. A trailing newline from `--from-env "$(cat key)"` or a
// piped file is stripped: unstripped, it would be smuggled into the upstream
// Authorization header.
func readProviderKey(cmd *cobra.Command) (string, error) {
	fromEnv, _ := cmd.Flags().GetString("from-env")
	fromStdin, _ := cmd.Flags().GetBool("stdin")
	literal, _ := cmd.Flags().GetString("key")

	sources := 0
	for _, set := range []bool{fromEnv != "", fromStdin, literal != ""} {
		if set {
			sources++
		}
	}
	if sources == 0 {
		return "", fmt.Errorf("provide the key with --from-env <VAR>, --stdin, or --key")
	}
	if sources > 1 {
		return "", fmt.Errorf("use only one of --from-env, --stdin, or --key")
	}

	var key string
	switch {
	case fromEnv != "":
		key = os.Getenv(fromEnv)
		if key == "" {
			return "", fmt.Errorf("$%s is not set (or is empty)", fromEnv)
		}
	case fromStdin:
		data, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && data == "" {
			return "", fmt.Errorf("failed to read the key from stdin: %w", err)
		}
		key = data
	default:
		key = literal
		ctx := display.FromCommand(cmd)
		ctx.Logger.Warn("--key puts the key in your shell history; prefer --from-env or --stdin")
	}

	key = strings.TrimSpace(key)
	if key == "" {
		return "", fmt.Errorf("the key is empty")
	}
	if len(key) > 4096 {
		return "", fmt.Errorf("the key is %d bytes; the maximum is 4096", len(key))
	}
	for _, r := range key {
		if r < 0x20 || r == 0x7f {
			return "", fmt.Errorf("the key contains a control character; it would corrupt the upstream Authorization header")
		}
	}
	return key, nil
}

func newAiFirewallKeyRemoveCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "remove <provider>",
		Short: "Remove this org's stored key for a provider",
		Long: `Delete the stored provider key. Until a new one is stored, every request
through that provider returns 403 provider_key_missing.`,
		Args: cobra.ExactArgs(1),
		RunE: runAiFirewallKeyRemove,
	}
	addAiFirewallCommonFlags(cmd)
	return cmd
}

func runAiFirewallKeyRemove(cmd *cobra.Command, args []string) error {
	if err := initAiFirewallOutput(cmd); err != nil {
		return err
	}
	slug := strings.TrimSpace(args[0])
	client, err := newPackageFirewallConfigClient(cmd)
	if err != nil {
		return err
	}
	ctx := display.FromCommand(cmd)
	resp, err := client.CliAiFirewallKey(envForCli(), vdb.CliAiFirewallKeyRequest{
		Provider: slug,
		Delete:   true,
	})
	if err != nil {
		return err
	}
	if ctx.IsJSON() {
		return ctx.Logger.ResultJSON(resp.Data)
	}
	ctx.Logger.Result(renderPackageFirewallResult(ctx, "Removed "+slug+" key", resp.Data))
	return nil
}

// --- settings ---

func newAiFirewallSettingsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "settings",
		Short: "Org-wide AI Firewall settings",
		Long: `Toggle org-wide settings.

--logs enables inference logging: the gateway records metadata about each proxied
request (model, policy decision, which guardrails matched, token usage, latency).
Prompts and completions are never stored. Requires a paid plan.`,
		Args: cobra.NoArgs,
		RunE: runAiFirewallSettings,
	}
	cmd.Flags().Bool("logs", false, "Enable inference logging (metadata only)")
	cmd.Flags().Bool("no-logs", false, "Disable inference logging")
	addAiFirewallCommonFlags(cmd)
	return cmd
}

func runAiFirewallSettings(cmd *cobra.Command, args []string) error {
	if err := initAiFirewallOutput(cmd); err != nil {
		return err
	}
	logs, _ := cmd.Flags().GetBool("logs")
	noLogs, _ := cmd.Flags().GetBool("no-logs")
	if logs && noLogs {
		return fmt.Errorf("--logs and --no-logs are mutually exclusive")
	}
	if !logs && !noLogs {
		return fmt.Errorf("specify --logs or --no-logs")
	}

	req := vdb.CliAiFirewallSettingsRequest{}
	v := logs
	req.LogsEnabled = &v

	client, err := newPackageFirewallConfigClient(cmd)
	if err != nil {
		return err
	}
	ctx := display.FromCommand(cmd)
	resp, err := client.CliAiFirewallSettings(envForCli(), req)
	if err != nil {
		return err
	}
	if ctx.IsJSON() {
		return ctx.Logger.ResultJSON(resp.Data)
	}
	ctx.Logger.Result(renderPackageFirewallResult(ctx, "AI Firewall settings updated", resp.Data))
	return nil
}
