package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
	configschemas "github.com/vulnetix/config-schemas"

	"github.com/vulnetix/cli/v4/internal/display"
	"github.com/vulnetix/cli/v4/pkg/vdb"
)

// `config set package-firewall` in its policy form (thresholds and blocks, not
// a mirror) is a documented alias of `config apply` for the
// PackageFirewallPolicy kind: the flags become the document's spec, which the
// engine merges into the tenant's policy (a field left out keeps its value),
// as manager "console". The mirror form and any credential the engine refuses
// keep the legacy endpoint, with a deprecation warning.

// packageFirewallSpecFromRequest maps the legacy request onto
// PackageFirewallPolicy.spec.
func packageFirewallSpecFromRequest(req vdb.CliPackageFirewallConfigRequest) map[string]any {
	spec := map[string]any{}
	section := func(name string) map[string]any {
		m, ok := spec[name].(map[string]any)
		if !ok {
			m = map[string]any{}
			spec[name] = m
		}
		return m
	}
	if req.CvssThreshold != nil {
		section("thresholds")["cvss"] = *req.CvssThreshold
	}
	if req.EpssThreshold != nil {
		section("thresholds")["epss"] = *req.EpssThreshold
	}
	if req.CessThreshold != nil {
		section("thresholds")["cess"] = *req.CessThreshold
	}
	for name, v := range map[string]*bool{
		"malware": req.BlockMalware, "eol": req.BlockEol, "kev": req.BlockKev,
		"weaponized": req.BlockWeaponized, "active": req.BlockActive,
		"poc": req.BlockPoc, "badActors": req.BlockBadActors,
	} {
		if v != nil {
			section("block")[name] = *v
		}
	}
	if req.CooldownDays != nil {
		spec["cooldownDays"] = *req.CooldownDays
	}
	if req.VersionLag != nil {
		spec["versionLag"] = *req.VersionLag
	}
	return spec
}

// packageFirewallPolicyViaEngine applies the policy through the config engine.
// handled is false when the legacy endpoint must run, with the reason.
func packageFirewallPolicyViaEngine(cmd *cobra.Command, req vdb.CliPackageFirewallConfigRequest) (handled bool, reason string, err error) {
	a, aerr := resolveConfigAuth()
	if aerr != nil {
		return false, "no credential for the config engine", nil
	}
	client := newConfigEngineClient(a)
	doc := map[string]any{
		"apiVersion": configschemas.APIVersion,
		"kind":       "PackageFirewallPolicy",
		"metadata":   map[string]any{"name": "default"},
		"spec":       packageFirewallSpecFromRequest(req),
	}
	ereq := configRequest{Manager: qualityGateManager, Documents: []any{doc}}
	p, _, perr := client.Plan(cmd.Context(), ereq)
	if perr != nil {
		if why := engineFallbackReason(perr, a); why != "" {
			return false, why, nil
		}
		return true, "", explainConfigAuth(perr, a)
	}
	if len(p.Blocking) > 0 {
		// A blocked plan is the engine protecting the object; the legacy
		// endpoint would go round it.
		fmt.Fprint(cmd.ErrOrStderr(), renderConfigPlan(p))
		return true, "", &configPlanBlockedError{n: len(p.Blocking)}
	}
	if p.needsApply() {
		ereq.PlanHash = p.PlanHash
		res, aerr2 := client.Apply(cmd.Context(), ereq)
		if aerr2 != nil {
			if why := engineFallbackReason(aerr2, a); why != "" {
				return false, why, nil
			}
			return true, "", explainConfigApplyError(aerr2, a)
		}
		if res.incomplete() {
			return true, "", &configApplyIncompleteError{failed: len(res.failedItems()), partial: res.Partial, counted: res.Failed}
		}
	}
	return true, "", nil
}

// renderPackageFirewallAfterEngine prints what the legacy command printed: the
// stored policy, read back through the same /v2 read the legacy path uses. If
// that read is not possible (an unreadable credential), it prints the spec sent.
func renderPackageFirewallAfterEngine(cmd *cobra.Command, req vdb.CliPackageFirewallConfigRequest) error {
	ctx := display.FromCommand(cmd)
	data := map[string]any{"config": packageFirewallSpecFromRequest(req)}
	if client, err := newPackageFirewallConfigClient(cmd); err == nil {
		if resp, err := client.CliPackageFirewallGet(envForCli()); err == nil {
			data = resp.Data
		}
	}
	if ctx.IsJSON() {
		return ctx.Logger.ResultJSON(data)
	}
	ctx.Logger.Result(renderPackageFirewallResult(ctx, "Package Firewall policy updated", data))
	return nil
}
