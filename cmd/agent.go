package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/vulnetix/cli/v3/internal/agent"
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

	agentCmd.AddCommand(agentHookCmd)
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
