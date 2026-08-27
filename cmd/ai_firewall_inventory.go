package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/pkg/vdb"
)

// --- inventory ---

func newAiFirewallInventoryCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inventory",
		Short: "List the tools, MCP servers and skills the gateway has seen agents carry",
		Long: `Show every tool, MCP server and skill this organisation's agents actually carry.

A repository scan finds the AI that is written down. This finds what ran: these
APIs are stateless, so a client re-sends its whole tool array every turn, and an
MCP server somebody wired into a local config on Tuesday — holding a token for
the issue tracker — is in no manifest but in every request that agent makes.
Pair it with 'vulnetix aibom', which covers the declared half.

Each row is graded by how it was learnt:

  declared   read verbatim from a request
  invoked    seen being called
  inferred   derived from a naming convention

The grade is shown rather than smoothed over, so a convention is never read as
a protocol fact.

It is metadata only — a tool name, an MCP server host, a user-agent. No prompt,
completion, tool argument or tool result is involved, which is why the gateway
records this for every organisation rather than only those that turned on
inference logging.

Examples:
  vulnetix ai-firewall inventory
  vulnetix ai-firewall inventory --kind mcp_server
  vulnetix ai-firewall inventory --client claude-code --search github
  vulnetix ai-firewall inventory -o json
  vulnetix ai-firewall inventory --clear`,
		Args: cobra.NoArgs,
		RunE: runAiFirewallInventory,
	}
	cmd.Flags().String("kind", "", "Filter by kind: tool, mcp_server or skill")
	cmd.Flags().String("client", "", "Filter by client name, e.g. claude-code")
	cmd.Flags().String("search", "", "Substring match on the capability's identity")
	cmd.Flags().Int("limit", 200, "Maximum rows to return (1-1000)")
	cmd.Flags().Bool("clear", false, "Delete the whole inventory instead of reading it")
	_ = cmd.RegisterFlagCompletionFunc("kind", cobra.FixedCompletions(
		[]string{"tool", "mcp_server", "skill"}, cobra.ShellCompDirectiveNoFileComp))
	addAiFirewallCommonFlags(cmd)
	return cmd
}

func runAiFirewallInventory(cmd *cobra.Command, args []string) error {
	if err := initAiFirewallOutput(cmd); err != nil {
		return err
	}
	ctx := display.FromCommand(cmd)

	kind, _ := cmd.Flags().GetString("kind")
	switch strings.TrimSpace(kind) {
	case "", "tool", "mcp_server", "skill":
	default:
		return fmt.Errorf("--kind must be one of: tool, mcp_server, skill")
	}
	limit, _ := cmd.Flags().GetInt("limit")
	if limit < 1 || limit > 1000 {
		return fmt.Errorf("--limit must be between 1 and 1000")
	}

	client, err := newPackageFirewallConfigClient(cmd)
	if err != nil {
		return err
	}
	clientName, _ := cmd.Flags().GetString("client")
	search, _ := cmd.Flags().GetString("search")
	clear, _ := cmd.Flags().GetBool("clear")

	resp, err := client.CliAiFirewallInventory(envForCli(), vdb.CliAiFirewallInventoryRequest{
		Kind:   strings.TrimSpace(kind),
		Client: strings.TrimSpace(clientName),
		Search: strings.TrimSpace(search),
		Limit:  limit,
		Clear:  clear,
	})
	if err != nil {
		return err
	}
	inv := resp.Data

	if ctx.IsJSON() {
		return ctx.Logger.ResultJSON(inv)
	}

	if clear {
		ctx.Logger.Result(fmt.Sprintf("Inventory cleared: %d entr%s removed.",
			inv.Removed, pluralSuffixIES(inv.Removed)))
		return nil
	}

	t := ctx.Term
	if len(inv.Entries) == 0 {
		ctx.Logger.Result("No AI capabilities observed yet. The inventory fills as agents send requests through the gateway.")
		return nil
	}

	cols := []display.Column{
		{Header: "KIND"}, {Header: "NAME"}, {Header: "CLIENT"}, {Header: "EVIDENCE"},
	}
	rows := make([][]string, 0, len(inv.Entries)*2)
	for _, e := range inv.Entries {
		name := e.ClientName
		if e.ClientVersion != "" {
			name += " " + e.ClientVersion
		}
		if name == "" {
			name = "unknown"
		}
		rows = append(rows, []string{e.Kind, e.Identity, name, e.Source})
		// An MCP server's host is the part that matters and is too long for the
		// identity column, so it gets its own dimmed continuation row.
		if e.Detail != "" {
			rows = append(rows, []string{"", display.Muted(t, e.Detail), "", ""})
		}
	}

	var b strings.Builder
	b.WriteString(display.Table(t, cols, rows))
	b.WriteString("\n")
	b.WriteString(display.Muted(t, fmt.Sprintf("# %s · %s · %s",
		pluralise("client", distinctClients(inv.Entries)),
		pluralise("MCP server", inv.Counts["mcp_server"]),
		pluralise("tool", inv.Counts["tool"]))))
	if inv.Counts["skill"] > 0 {
		b.WriteString(display.Muted(t, " · "+pluralise("skill", inv.Counts["skill"])))
	}
	if inv.Truncated {
		b.WriteString("\n" + display.Muted(t,
			fmt.Sprintf("# Truncated at --limit %d; there may be more.", limit)))
	}
	ctx.Logger.Result(strings.TrimRight(b.String(), "\n"))
	return nil
}

func distinctClients(entries []vdb.AiFirewallInventoryEntry) int {
	seen := map[string]bool{}
	for _, e := range entries {
		if e.ClientName != "" {
			seen[e.ClientName] = true
		}
	}
	return len(seen)
}

// pluralSuffixIES picks the suffix for "entr(y|ies)".
func pluralSuffixIES(n int64) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
