package cmd

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/vulnetix/cli/v4/internal/display"
	"github.com/vulnetix/cli/v4/internal/platformiac"
	aifw "github.com/vulnetix/cli/v4/pkg/aifirewall"
)

// `ai-firewall apply` and `ai-firewall export` are documented aliases of
// `config apply` and `config export` for the AiFirewallPolicy kind. They take
// the same policy file as before and send it to the config engine as manager
// "console" (the same as the deprecated `config set` aliases), so the engine's
// plan, ownership and apply rules govern it and `config plan` shows the same
// result.
//
// The legacy path stays, with a deprecation warning, for everyone who cannot
// use the engine: an ApiKey is a member and cannot plan or apply (401/403),
// the engine may not be deployed where the caller points (404), and a local
// --catalog baseline has no document form.

const aiFirewallManager = "console"

// aiFirewallDeprecation is printed when the legacy endpoints are used.
func aiFirewallLegacy(cmd *cobra.Command, command, reason string) {
	fmt.Fprintf(cmd.ErrOrStderr(), "Deprecated: the legacy AI Firewall endpoints behind 'vulnetix ai-firewall %s' will be removed; sign in as an owner or admin, or set VULNETIX_API_KEY and VULNETIX_ORG_ID for an admin service account, so it runs through the config engine.\nUsing the legacy endpoints: %s.\n", command, reason)
}

// aiFirewallDocument loads the policy document the alias sends: the file named
// with --file, else the well-known file or an AiFirewallPolicy under
// .vulnetix/config.
func aiFirewallDocument(cmd *cobra.Command, path string) (*configDocument, error) {
	var doc *platformiac.Document
	if cmd.Flags().Changed("file") {
		docs, err := platformiac.Discover(platformiac.Options{Root: ".", Files: []string{path}})
		if err != nil {
			return nil, err
		}
		for i := range docs {
			if docs[i].Kind == aifw.PolicyKind {
				doc = &docs[i]
				break
			}
		}
	} else {
		var err error
		if doc, err = platformiac.LoadSingleton(".", aifw.PolicyKind); err != nil {
			return nil, err
		}
	}
	if doc == nil {
		return nil, fmt.Errorf("no AI Firewall policy: write %s or an AiFirewallPolicy document in %s (vulnetix ai-firewall export writes one)", aifw.DefaultPolicyPath, platformiac.ConfigDir)
	}
	cd := configDocument{Document: doc.Document, Path: doc.Path, Index: doc.Index}
	if problems, err := validateConfigDocuments([]configDocument{cd}); err != nil {
		return nil, err
	} else if len(problems) > 0 {
		return nil, fmt.Errorf("%s", problems[0])
	}
	return &cd, nil
}

// aiFirewallApplyViaEngine runs `ai-firewall apply` through the config engine.
// handled is false when the legacy path must run, with the reason.
func aiFirewallApplyViaEngine(cmd *cobra.Command) (handled bool, reason string, err error) {
	if c, _ := cmd.Flags().GetString("catalog"); c != "" {
		return false, "a local --catalog baseline has no document form", nil
	}
	a, aerr := resolveConfigAuth()
	if aerr != nil {
		return false, "no credential for the config engine", nil
	}
	path, _ := cmd.Flags().GetString("file")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	prune, _ := cmd.Flags().GetBool("prune")
	force, _ := cmd.Flags().GetBool("force")
	noBaseline, _ := cmd.Flags().GetBool("no-baseline")

	doc, err := aiFirewallDocument(cmd, path)
	if err != nil {
		return true, "", err
	}
	value, _ := doc.Value.(map[string]any)
	if noBaseline {
		spec, _ := value["spec"].(map[string]any)
		if spec == nil {
			spec = map[string]any{}
			value["spec"] = spec
		}
		b, _ := spec["baseline"].(map[string]any)
		if b == nil {
			b = map[string]any{}
			spec["baseline"] = b
		}
		b["enabled"] = false
	}
	if !cmd.Flags().Changed("ref") {
		// the document's own spec.baseline.ref wins
	} else if ref, _ := cmd.Flags().GetString("ref"); ref != "" {
		spec, _ := value["spec"].(map[string]any)
		if spec != nil {
			b, _ := spec["baseline"].(map[string]any)
			if b == nil {
				b = map[string]any{}
				spec["baseline"] = b
			}
			b["ref"] = ref
		}
	}

	client := newConfigEngineClient(a)
	req := configRequest{Manager: aiFirewallManager, Prune: prune, SourceRef: configSourceRef("."), Documents: []any{value}}
	p, _, perr := client.Plan(cmd.Context(), req)
	if perr != nil {
		if why := engineFallbackReason(perr, a); why != "" {
			return false, why, nil
		}
		return true, "", explainConfigAuth(perr, a)
	}
	if !force {
		if err := checkConfigOrg([]configDocument{*doc}, p.Tenant); err != nil {
			return true, "", err
		}
	}
	ctx := display.FromCommand(cmd)
	if len(p.Blocking) > 0 {
		fmt.Fprint(cmd.ErrOrStderr(), renderConfigPlan(p))
		return true, "", &configPlanBlockedError{n: len(p.Blocking)}
	}
	if dryRun || !p.needsApply() {
		if ctx.IsJSON() {
			return true, "", ctx.Logger.ResultJSON(map[string]any{"dryRun": dryRun, "file": doc.Path, "plan": p})
		}
		ctx.Logger.Result(renderConfigPlan(p))
		return true, "", nil
	}
	req.PlanHash = p.PlanHash
	res, aerr2 := client.Apply(cmd.Context(), req)
	if aerr2 != nil {
		return true, "", explainConfigApplyError(aerr2, a)
	}
	if ctx.IsJSON() {
		if err := ctx.Logger.ResultJSON(map[string]any{"dryRun": false, "file": doc.Path, "applied": res.Summary, "items": res.Items}); err != nil {
			return true, "", err
		}
	} else {
		ctx.Logger.Result(renderConfigApplyResult(res))
	}
	if res.incomplete() {
		return true, "", &configApplyIncompleteError{failed: len(res.failedItems()), partial: res.Partial, counted: res.Failed}
	}
	return true, "", nil
}

// aiFirewallExportViaEngine runs `ai-firewall export` through the config
// engine's export of the AiFirewallPolicy kind.
func aiFirewallExportViaEngine(cmd *cobra.Command) (handled bool, reason string, err error) {
	a, aerr := resolveConfigAuth()
	if aerr != nil {
		return false, "no credential for the config engine", nil
	}
	body, eerr := newConfigEngineClient(a).Export(cmd.Context(), url.Values{"kind": {aifw.PolicyKind}, "format": {"yaml"}}, nil)
	if eerr != nil {
		if why := engineFallbackReason(eerr, a); why != "" {
			return false, why, nil
		}
		return true, "", explainConfigAuth(eerr, a, "AiFirewallPolicy exports need an owner or admin")
	}
	ctx := display.FromCommand(cmd)
	if toStdout, _ := cmd.Flags().GetBool("stdout"); toStdout {
		ctx.Logger.Result(string(body))
		return true, "", nil
	}
	path, _ := cmd.Flags().GetString("file")
	force, _ := cmd.Flags().GetBool("force")
	if _, err := os.Stat(path); err == nil && !force {
		return true, "", fmt.Errorf("%s already exists; pass --force to overwrite", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return true, "", err
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return true, "", err
	}
	if ctx.IsJSON() {
		return true, "", ctx.Logger.ResultJSON(map[string]any{"path": path})
	}
	ctx.Logger.Result("Wrote " + path + "\n\nReview it, then apply with:\n  vulnetix ai-firewall apply -f " + path + " --dry-run")
	return true, "", nil
}
