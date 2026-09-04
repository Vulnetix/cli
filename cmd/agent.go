package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/vulnetix/cli/v3/internal/agent"
	"github.com/vulnetix/cli/v3/pkg/auth"
)

var (
	agentHookEvent string
	agentHookRoot  string
)

// agentHookActive reports whether this process is answering a coding agent's
// hook.
//
// Like the language server, a hook's stdout is a protocol stream the host
// parses, so nothing else may write to it: a banner ahead of the JSON is not
// cosmetic, it makes the response unparseable. It is also not a command a person
// ran, and it fires once per tool call, so per-command analytics and a GitHub
// update poll are both wrong for it.
var agentHookActive bool

// AgentHookActive reports whether the process is answering a hook. Read by
// printBanner and startupHooks.
func AgentHookActive() bool { return agentHookActive }

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Wire AI coding agents to Vulnetix",
	Long: `Connect a coding agent to Vulnetix.

The agent surface answers at the moment a decision is made. When an agent is
about to add a dependency, 'agent hook' checks it against this repository's
Safe Harbour policy and reports what it found into the agent's own context, so
the actor that would fix the problem is the one told about it.

It says nothing at all when the policy is already satisfied. That silence is the
feature: a guard that comments on every install is one people switch off.`,
}

var agentHookCmd = &cobra.Command{
	Use:   "hook",
	Short: "Answer a coding agent's lifecycle hook",
	Long: `Read a hook payload on standard input and write the response on standard output.

Intended to be run by a coding agent rather than by hand. 'vulnetix agent
install' wires it into every agent it finds.

The response uses the two shapes Claude Code and OpenAI Codex both accept:
additionalContext to report without interrupting, and a deny decision with a
reason for the cases where proceeding is never right. Nothing is printed when
there is nothing to say, which is the common case.

Exit status is always 0. A hook stands between an agent and the tool it asked to
run, so an unreadable payload, an unreachable API or a missing credential all
mean "no opinion" rather than a failure the user has to deal with mid-task.`,
	Args: cobra.NoArgs,
	RunE: runAgentHook,
}

func init() {
	agentHookCmd.Flags().StringVar(&agentHookEvent, "event", "",
		"Hook event name, when the payload does not carry one (PreToolUse, PostToolUse, UserPromptSubmit, SessionStart, Stop)")
	agentHookCmd.Flags().StringVar(&agentHookRoot, "root", "",
		"Repository root. Defaults to the payload's cwd, then the working directory.")

	agentInstallCmd.Flags().StringArrayVar(&agentInstallHosts, "agent", nil,
		"Wire only this agent (repeatable). Default is every agent detected on this machine.")
	agentInstallCmd.Flags().BoolVar(&agentInstallDryRun, "dry-run", false,
		"Report what would change without writing anything")
	agentInstallCmd.Flags().BoolVar(&agentInstallNoHooks, "no-hooks", false,
		"Skip hook configuration")
	agentHostsCmd.Flags().StringVarP(&agentHostsOutput, "output", "o", "pretty",
		"Output format: pretty or json")

	agentCmd.AddCommand(agentHookCmd)
	agentCmd.AddCommand(agentInstallCmd)
	agentCmd.AddCommand(agentHostsCmd)
	rootCmd.AddCommand(agentCmd)

	// Set as early as possible: startupHooks runs via cobra.OnInitialize, after
	// flag parsing but before RunE, and printBanner runs in PersistentPreRun.
	// Both need to know that stdout belongs to the host.
	cobra.OnInitialize(func() {
		if agentHookCmd.CalledAs() != "" {
			agentHookActive = true
		}
	})
}

func runAgentHook(cmd *cobra.Command, _ []string) error {
	// Everything below reports through the response, or not at all. The one
	// thing this command must never do is fail in a way that surfaces to
	// someone mid-task as a broken tool.
	payload, err := agent.DecodePayload(cmd.InOrStdin())
	if err != nil {
		return nil
	}

	if payload.HookEventName == "" {
		payload.HookEventName = agent.Event(agentHookEvent)
	}
	if payload.HookEventName == "" {
		return nil
	}

	root := agentHookRoot
	if root == "" {
		root = payload.CWD
	}
	if root == "" {
		if wd, wdErr := os.Getwd(); wdErr == nil {
			root = wd
		}
	}

	policy, policyErr := agent.LoadPolicy(root)
	if policyErr != nil {
		// A malformed policy file is worth saying out loud, because the
		// alternative is guarding on something other than what was written. It
		// goes to stderr, where it reaches the user without being mistaken for
		// a verdict about a package.
		fmt.Fprintf(cmd.ErrOrStderr(), "vulnetix agent: %v — using defaults\n", policyErr)
	}

	runner := agent.Runner{
		Policy: policy,
		Lookup: agent.NewVDBLookup(root, version),
		Root:   root,
	}

	resp := runner.Run(context.Background(), payload)
	if err := resp.Encode(cmd.OutOrStdout()); err != nil {
		return nil
	}
	return nil
}

var (
	agentInstallHosts   []string
	agentInstallDryRun  bool
	agentInstallNoHooks bool
	agentHostsOutput    string
)

var agentInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Wire the coding agents on this machine to Vulnetix",
	Long: `Detect installed coding agents and configure them.

Existing configuration is preserved: this CLI's entry is added or updated in
place and everything else in the file is written back untouched. Re-running is
safe and reports that nothing changed.

Hooks are only configured for hosts whose hook contract has been verified
against this CLI. A host that documents one this build has not tested is wired
for skills and said so, rather than being promised support that was never run.`,
	Args: cobra.NoArgs,
	RunE: runAgentInstall,
}

var agentHostsCmd = &cobra.Command{
	Use:   "hosts",
	Short: "List the coding agents this CLI can wire, and what it can wire for each",
	Long: `Print the support matrix.

This is the source of truth the documentation and the marketing support tables
are generated from, so a page cannot claim a capability the installer does not
implement.`,
	Args: cobra.NoArgs,
	RunE: runAgentHosts,
}

func runAgentInstall(cmd *cobra.Command, _ []string) error {
	hosts := agent.DetectHosts()
	if len(agentInstallHosts) > 0 {
		hosts = nil
		for _, id := range agentInstallHosts {
			h, ok := agent.HostByID(id)
			if !ok {
				return fmt.Errorf("unknown agent %q; run 'vulnetix agent hosts' for the list", id)
			}
			hosts = append(hosts, h)
		}
	}

	out := cmd.OutOrStdout()
	if len(hosts) == 0 {
		fmt.Fprintln(out, "No coding agents detected on this machine.")
		fmt.Fprintln(out, "Name one explicitly with --agent, or run 'vulnetix agent hosts' for the list.")
		return nil
	}

	opts := agent.InstallOptions{DryRun: agentInstallDryRun, Hooks: !agentInstallNoHooks}

	for _, h := range hosts {
		fmt.Fprintf(out, "%s\n", h.Name)

		if opts.Hooks {
			res := agent.InstallHooks(h, opts)
			switch {
			case res.Err != nil:
				fmt.Fprintf(out, "  hooks    %v\n", res.Err)
			case len(res.Wired) == 0:
				// Nothing to report beyond the note explaining why.
			case res.Changed && opts.DryRun:
				fmt.Fprintf(out, "  hooks    would configure %s\n", h.HookConfig)
			case res.Changed:
				fmt.Fprintf(out, "  hooks    configured %s\n", h.HookConfig)
			default:
				fmt.Fprintf(out, "  hooks    already configured\n")
			}
			for _, note := range res.Notes {
				fmt.Fprintf(out, "  note     %s\n", note)
			}
		}

		for _, dir := range h.SkillDirs {
			fmt.Fprintf(out, "  skills   %s\n", dir)
		}
		if h.MCP {
			fmt.Fprintf(out, "  mcp      https://mcp.vulnetix.com/mcp\n")
		}
	}

	fmt.Fprintln(out)
	reportAgentAuth(out)
	return nil
}

// reportAgentAuth says which credential the guard will run on, because the
// answer changes the rate limit a developer gets and the fix is one URL.
func reportAgentAuth(out io.Writer) {
	creds, err := auth.LoadCredentials()
	switch {
	case err == nil && creds != nil && !auth.IsCommunity(creds):
		fmt.Fprintln(out, "Authenticated.")
	default:
		fmt.Fprintln(out, "Running on the shared Community tier: reads work, rate limits are shared.")
		fmt.Fprintln(out, "A free Community key with its own quota:")
		fmt.Fprintln(out, "  https://www.vulnetix.com/resolve/register, then 'vulnetix auth login'.")
	}
}

func runAgentHosts(cmd *cobra.Command, _ []string) error {
	out := cmd.OutOrStdout()
	if agentHostsOutput == "json" {
		return json.NewEncoder(out).Encode(agent.Hosts)
	}

	fmt.Fprintf(out, "%-16s %-18s %-10s %-6s %-5s %s\n", "ID", "NAME", "INSTALLED", "SKILLS", "HOOKS", "MCP")
	for _, h := range agent.Hosts {
		fmt.Fprintf(out, "%-16s %-18s %-10s %-6s %-5s %s\n",
			h.ID, h.Name,
			yesNo(h.Installed()),
			yesNo(h.Supports(agent.SurfaceSkills)),
			yesNo(h.Supports(agent.SurfaceHooks)),
			yesNo(h.Supports(agent.SurfaceMCP)))
	}
	return nil
}
