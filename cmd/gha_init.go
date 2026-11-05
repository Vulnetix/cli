package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v4/internal/ghainit"
	"gopkg.in/yaml.v3"
)

var (
	ghaInitCheck    bool
	ghaInitDryRun   bool
	ghaInitForce    bool
	ghaInitRef      string
	ghaInitTriggers string
	ghaInitRunner   string
)

const dependabotActions = `version: 2
updates:
  - package-ecosystem: github-actions
    directory: "/"
    schedule:
      interval: weekly
    cooldown:
      default-days: 3
    # One pull request for a batch of bumps, since each must re-run gh actions-lock.
    groups:
      actions:
        patterns: ["*"]
`

var ghaInitCmd = &cobra.Command{
	Use:   "init [path]",
	Short: "Write this repository's managed Vulnetix workflow",
	Long: `Write .github/workflows/vulnetix.yml from what the repository is made of and
.vulnetix/workflow.yaml.

A language counts at 10 or more files and 2% of the source. One or two languages
get a sast/<language> job each, and the largest job carries a rest step so the
jobs together cover what the high-level sast action covers; three or more use the
high-level action. Package managers work the same way with sca/<manager>.

Refs are written as @v4. Run gh actions-lock afterwards to narrow them to exact
tags and lock them; --check ignores refs, so a locked workflow stays current.

--check writes nothing and exits 1 when the file on disk differs from what the
policy renders, which is the drift check for a workflow.`,
	Example: `  vulnetix gha init
  vulnetix gha init --triggers pr --runner vulnetix-local
  vulnetix gha init --check`,
	Args:          cobra.MaximumNArgs(1),
	SilenceUsage:  true,
	SilenceErrors: false,
	RunE: func(cmd *cobra.Command, args []string) error {
		root := "."
		if len(args) == 1 {
			root = args[0]
		}
		policy, err := ghainit.LoadPolicy(root)
		if err != nil {
			return err
		}
		newPolicy := policy == nil
		if newPolicy {
			policy = ghainit.DefaultPolicy()
			if ghaInitTriggers != "" {
				policy.Triggers = ghaInitTriggers
			}
			if cmd.Flags().Changed("runner") {
				policy.Runner = ghaInitRunner
			}
			if err := policy.Validate(); err != nil {
				return err
			}
		}
		sig, err := ghainit.Detect(root)
		if err != nil {
			return err
		}
		rendered := ghainit.Render(policy, sig, ghainit.Options{Ref: ghaInitRef})
		path := filepath.Join(root, ghainit.WorkflowPath)
		existing, readErr := os.ReadFile(path)

		if ghaInitCheck {
			if readErr != nil {
				return fmt.Errorf("%s: %w", ghainit.WorkflowPath, readErr)
			}
			if ghainit.Normalize(string(existing)) != ghainit.Normalize(rendered) {
				return fmt.Errorf("%s is out of date: run vulnetix gha init", ghainit.WorkflowPath)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s is current\n", ghainit.WorkflowPath)
			return nil
		}
		if ghaInitDryRun {
			fmt.Fprint(cmd.OutOrStdout(), rendered)
			return nil
		}
		if readErr == nil && !ghainit.IsManaged(string(existing)) && !ghaInitForce {
			return fmt.Errorf("%s exists and is not managed by this command; move your jobs out of it or pass --force", ghainit.WorkflowPath)
		}
		if err := writeRepoFile(root, ghainit.WorkflowPath, []byte(rendered)); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "wrote %s (languages %v, package managers %v)\n", ghainit.WorkflowPath, sig.Languages, sig.Managers)
		if newPolicy {
			raw, err := yaml.Marshal(policy)
			if err != nil {
				return err
			}
			if err := writeRepoFile(root, ghainit.PolicyPath, raw); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", ghainit.PolicyPath)
		}
		dependabot := ".github/dependabot.yml"
		if _, err := os.Stat(filepath.Join(root, dependabot)); os.IsNotExist(err) {
			if err := writeRepoFile(root, dependabot, []byte(dependabotActions)); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", dependabot)
		}
		return nil
	},
}

func writeRepoFile(root, rel string, data []byte) error {
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, data, 0o644)
}

func init() {
	ghaInitCmd.Flags().BoolVar(&ghaInitCheck, "check", false, "Exit 1 when the workflow on disk differs from what the policy renders; write nothing")
	ghaInitCmd.Flags().BoolVar(&ghaInitDryRun, "dry-run", false, "Print the workflow and write nothing")
	ghaInitCmd.Flags().BoolVar(&ghaInitForce, "force", false, "Replace a vulnetix.yml this command did not write")
	ghaInitCmd.Flags().StringVar(&ghaInitRef, "ref", "v4", "Ref the workflow's Vulnetix actions use")
	ghaInitCmd.Flags().StringVar(&ghaInitTriggers, "triggers", "", "With no policy file: pr, push or belai")
	ghaInitCmd.Flags().StringVar(&ghaInitRunner, "runner", "vulnetix-local", "With no policy file: self-hosted runner label; empty uses ubuntu-latest")
	ghaCmd.AddCommand(ghaInitCmd)
}
