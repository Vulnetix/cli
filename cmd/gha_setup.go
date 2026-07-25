package cmd

// `vulnetix gha setup <tool>`: wire a third-party scanner into this repository.
//
// The workflow it writes is the same shape that runs in production: each scanner
// job uploads its report as a workflow artifact, and a single publish job hands
// every artifact to Vulnetix attributed to the tool that produced it. The job
// definitions come from internal/ghasetup's catalog, which is also what the
// published documentation examples are generated from, so what you read and
// what this writes cannot drift apart.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/ghasetup"
)

var (
	ghaSetupList       bool
	ghaSetupDryRun     bool
	ghaSetupForce      bool
	ghaSetupSelfHosted []string
	ghaSetupAll        bool
)

var ghaSetupCmd = &cobra.Command{
	Use:   "setup [tool...]",
	Short: "Add a third-party scanner to this repository's workflows",
	Long: `Add or update the GitHub Actions workflow that publishes a third-party
scanner's reports to Vulnetix.

The workflow is written to .github/workflows/vulnetix-scanners.yml. Running this
again for another tool adds that tool alongside the ones already there rather
than replacing them.

Each scanner runs as its own job and uploads its report as a workflow artifact.
One publish job then hands every artifact to Vulnetix in a single call,
attributed to the tool that produced it, so a gosec report is recorded as
gosec, not as Vulnetix.

The Vulnetix CLI is installed unpinned: install.sh resolves the latest release,
so the workflow keeps working without anyone returning to bump a version. The
third-party scanners themselves are pinned, because there a reproducible scan
matters more than being current.

Examples:
  vulnetix gha setup --list
  vulnetix gha setup gosec
  vulnetix gha setup trivy-fs trivy-config checkov
  vulnetix gha setup --all --dry-run`,
	RunE: runGHASetup,
}

func runGHASetup(cmd *cobra.Command, args []string) error {
	dctx := display.FromCommand(cmd)
	t := dctx.Term

	catalog, err := ghasetup.Load()
	if err != nil {
		return err
	}

	if ghaSetupList {
		printToolCatalog(dctx, t, catalog)
		return nil
	}

	if ghaSetupAll {
		args = catalog.IDs()
	}
	if len(args) == 0 {
		return fmt.Errorf("name at least one tool, or pass --list to see what is available")
	}

	// Reject unknown tools before touching the filesystem, so a typo in the
	// third of three names does not leave a half-written workflow.
	for _, id := range args {
		if _, ok := catalog.Find(id); !ok {
			msg := fmt.Sprintf("unknown tool %q", id)
			if s := catalog.Suggest(id); len(s) > 0 {
				msg += fmt.Sprintf("; did you mean %s?", strings.Join(s, ", "))
			} else {
				msg += fmt.Sprintf("; run 'vulnetix gha setup --list' (%d available)", len(catalog.Tools))
			}
			return fmt.Errorf("%s", msg)
		}
	}

	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	root, err := ghasetup.RepoRoot(cwd)
	if err != nil || root == "" {
		return fmt.Errorf("not inside a git repository: a workflow file has nowhere to go")
	}

	// A workflow file only does anything on GitHub. Warn rather than refuse:
	// mirrors, forks yet to be pushed, and unusually named Enterprise hosts are
	// all legitimate reasons to write it anyway.
	remote := ghasetup.DetectRemote(root)
	switch {
	case remote.URL == "":
		dctx.Logger.Warn("This repository has no 'origin' remote. GitHub Actions workflows only run on GitHub.")
	case !remote.IsGitHub:
		dctx.Logger.Warnf("The 'origin' remote is %s, not GitHub. GitHub Actions workflows only run on GitHub, so this file will have no effect there.", orUnknownHost(remote.Host))
		dctx.Logger.Warn("For that platform see the CI/CD guides at https://docs.cli.vulnetix.com/docs/ci-cd/")
	}

	path := filepath.Join(root, ghasetup.WorkflowPath)

	// Merge with whatever is already wired up, so setting up a second tool does
	// not silently drop the first.
	selected := append([]string{}, args...)
	existing, err := os.ReadFile(path)
	switch {
	case err == nil:
		if !ghasetup.IsManaged(string(existing)) && !ghaSetupForce {
			return fmt.Errorf("%s exists but was not written by 'gha setup'.\n"+
				"This command regenerates the whole file, so it will not overwrite hand-written "+
				"workflows. Move it aside, or pass --force to replace it.", ghasetup.WorkflowPath)
		}
		already := ghasetup.ToolsInWorkflow(catalog, string(existing))
		selected = append(selected, already...)
	case !os.IsNotExist(err):
		return fmt.Errorf("read %s: %w", ghasetup.WorkflowPath, err)
	}

	content, err := ghasetup.Render(catalog, selected, ghasetup.Options{
		SelfHostedLabels: ghaSetupSelfHosted,
	})
	if err != nil {
		return err
	}

	added, kept := splitAddedKept(catalog, args, existing)

	if ghaSetupDryRun {
		dctx.Logger.Info(display.Bold(t, ghasetup.WorkflowPath+" (dry run, nothing written)"))
		dctx.Logger.Info("")
		fmt.Println(content)
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create .github/workflows: %w", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", ghasetup.WorkflowPath, err)
	}

	dctx.Logger.Info(display.Bold(t, "Wrote "+ghasetup.WorkflowPath))
	if len(added) > 0 {
		dctx.Logger.Infof("  added: %s", strings.Join(added, ", "))
	}
	if len(kept) > 0 {
		dctx.Logger.Infof("  kept:  %s", strings.Join(kept, ", "))
	}
	dctx.Logger.Info("")
	dctx.Logger.Info("Set these repository secrets so the publish job can authenticate:")
	dctx.Logger.Info("  VULNETIX_ORG_ID    your organisation uuid")
	dctx.Logger.Info("  VULNETIX_API_KEY   an API key for that organisation")
	dctx.Logger.Info("")
	dctx.Logger.Info("Then commit the workflow and push. After the run, `vulnetix gha status` reports what landed.")
	return nil
}

// splitAddedKept reports which of the requested tools are new to the workflow
// and which were already there, so the output does not claim to have added
// something that was present already.
func splitAddedKept(c *ghasetup.Catalog, requested []string, existing []byte) (added, kept []string) {
	present := map[string]bool{}
	if len(existing) > 0 {
		for _, id := range ghasetup.ToolsInWorkflow(c, string(existing)) {
			present[id] = true
		}
	}
	seen := map[string]bool{}
	for _, id := range requested {
		tool, ok := c.Find(id)
		if !ok || seen[tool.ID] {
			continue
		}
		seen[tool.ID] = true
		if present[tool.ID] {
			kept = append(kept, tool.ID)
		} else {
			added = append(added, tool.ID)
		}
	}
	for id := range present {
		if !seen[id] {
			kept = append(kept, id)
		}
	}
	sort.Strings(added)
	sort.Strings(kept)
	return added, kept
}

func printToolCatalog(dctx *display.Context, t *display.Terminal, c *ghasetup.Catalog) {
	byCategory := map[string][]ghasetup.Tool{}
	for _, tool := range c.Tools {
		byCategory[tool.Category] = append(byCategory[tool.Category], tool)
	}
	cats := make([]string, 0, len(byCategory))
	for k := range byCategory {
		cats = append(cats, k)
	}
	sort.Strings(cats)

	dctx.Logger.Info(display.Bold(t, fmt.Sprintf("%d scanners available", len(c.Tools))))
	dctx.Logger.Info("")
	for _, cat := range cats {
		dctx.Logger.Info(display.Bold(t, cat))
		tools := byCategory[cat]
		sort.Slice(tools, func(i, j int) bool { return tools[i].ID < tools[j].ID })
		for _, tool := range tools {
			dctx.Logger.Infof("  %-14s %s", tool.ID, tool.Description)
		}
		dctx.Logger.Info("")
	}
	dctx.Logger.Info("Add one with: vulnetix gha setup <tool>")
}

func orUnknownHost(h string) string {
	if strings.TrimSpace(h) == "" {
		return "not a recognised git host"
	}
	return h
}

func init() {
	ghaSetupCmd.Flags().BoolVar(&ghaSetupList, "list", false, "List the scanners that can be set up")
	ghaSetupCmd.Flags().BoolVar(&ghaSetupAll, "all", false, "Set up every scanner in the catalog")
	ghaSetupCmd.Flags().BoolVar(&ghaSetupDryRun, "dry-run", false, "Print the workflow instead of writing it")
	ghaSetupCmd.Flags().BoolVar(&ghaSetupForce, "force", false, "Replace an existing workflow that was not written by this command")
	ghaSetupCmd.Flags().StringSliceVar(&ghaSetupSelfHosted, "runs-on", nil, "Runner labels to use instead of ubuntu-latest (e.g. self-hosted,Linux,X64)")

	ghaCmd.AddCommand(ghaSetupCmd)
}
