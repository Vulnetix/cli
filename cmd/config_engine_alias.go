package cmd

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/spf13/cobra"
	configschemas "github.com/vulnetix/config-schemas"

	"github.com/vulnetix/cli/v4/internal/display"
	"github.com/vulnetix/cli/v4/pkg/vdb"
)

// `config set quality-gate` and `config set eol-policy` are deprecated aliases
// of `config apply`: they build a QualityGate document from their flags and
// send it to the config engine as manager "console" (an imperative edit, not a
// declaration from a repository). Their flags and output are unchanged.
//
// They must keep working for everyone who uses them today, and today they
// authenticate with an ApiKey, which is a member and so cannot plan or apply.
// So when the engine refuses the credential (401/403), is not deployed where
// the caller points (404), or the change is one the engine cannot express
// (unsetting a field), the command says why on stderr and takes the legacy
// /v2/cli.quality-gate-config path it always took.

// qualityGateManager is the manager the aliases apply as.
const qualityGateManager = "console"

// qualityGateSpecFromRequest maps the legacy request onto QualityGate.spec,
// the same mapping the engine's adapter uses (vdb-site config/qualitygate.go).
// why is non-empty when the request cannot be expressed as a document.
func qualityGateSpecFromRequest(req vdb.CliQualityGateConfigRequest) (spec map[string]any, why string) {
	if len(req.Clear) > 0 {
		return nil, "the config engine merges documents and cannot unset a setting ('null')"
	}
	spec = map[string]any{}
	set := func(path []string, v any) {
		m := spec
		for _, p := range path[:len(path)-1] {
			next, ok := m[p].(map[string]any)
			if !ok {
				next = map[string]any{}
				m[p] = next
			}
			m = next
		}
		m[path[len(path)-1]] = v
	}
	str := func(path []string, v *string) {
		if v != nil {
			set(path, *v)
		}
	}
	boolean := func(path []string, v *bool) {
		if v != nil {
			set(path, *v)
		}
	}
	integer := func(path []string, v *int) {
		if v != nil {
			set(path, *v)
		}
	}
	str([]string{"severity"}, req.Severity)
	str([]string{"exploits"}, req.Exploits)
	boolean([]string{"blockMalware"}, req.BlockMalware)
	boolean([]string{"blockUnpinned"}, req.BlockUnpinned)
	integer([]string{"cooldownDays"}, req.Cooldown)
	integer([]string{"versionLag"}, req.VersionLag)
	boolean([]string{"eol", "block"}, req.BlockEol)
	str([]string{"eol", "severities", "nextQuarter"}, req.EolNextQuarterSeverity)
	str([]string{"eol", "severities", "thisQuarter"}, req.EolThisQuarterSeverity)
	str([]string{"eol", "severities", "within30Days"}, req.EolWithin30DaysSeverity)
	str([]string{"eol", "severities", "retired"}, req.EolRetiredSeverity)
	str([]string{"scaAutofix", "strategy"}, req.ScaAutofixStrategy)
	integer([]string{"scaAutofix", "maxMajorBump"}, req.ScaAutofixMaxMajorBump)
	return spec, ""
}

// setQualityGate runs a deprecated `config set` alias: the engine first, the
// legacy endpoint when the engine cannot take the request.
func setQualityGate(cmd *cobra.Command, command, title string, req vdb.CliQualityGateConfigRequest) error {
	stderr := cmd.ErrOrStderr()
	fmt.Fprintf(stderr, "Deprecated: 'vulnetix config set %s' will be removed; declare a QualityGate document in .vulnetix/config/ and run 'vulnetix config apply'.\n", command)

	legacy := func(reason string) error {
		fmt.Fprintf(stderr, "Using the legacy quality-gate endpoint: %s.\n", reason)
		return setQualityGateLegacy(cmd, title, req)
	}

	spec, why := qualityGateSpecFromRequest(req)
	if why != "" {
		return legacy(why)
	}
	a, err := resolveConfigAuth("")
	if err != nil {
		return legacy("no credential for the config engine")
	}
	client := newConfigEngineClient(a)
	doc := map[string]any{
		"apiVersion": configschemas.APIVersion,
		"kind":       "QualityGate",
		"metadata":   map[string]any{"name": "default"},
		"spec":       spec,
	}
	ereq := configRequest{Manager: qualityGateManager, Documents: []any{doc}}

	p, _, err := client.Plan(cmd.Context(), ereq)
	if err != nil {
		if reason := engineFallbackReason(err, a); reason != "" {
			return legacy(reason)
		}
		return err
	}
	if len(p.Blocking) > 0 {
		// Not a fallback: a blocked plan is the engine protecting the object
		// (most often, another manager owns the gate). Going round it through
		// the legacy endpoint would undo that.
		fmt.Fprint(stderr, renderConfigPlan(p))
		return &configPlanBlockedError{n: len(p.Blocking)}
	}
	if p.needsApply() {
		ereq.PlanHash = p.PlanHash
		if _, err := client.Apply(cmd.Context(), ereq); err != nil {
			if reason := engineFallbackReason(err, a); reason != "" {
				return legacy(reason)
			}
			return explainConfigApplyError(err, a)
		}
	}
	return renderQualityGateAfterEngine(cmd, title, spec)
}

// engineFallbackReason says why err sends an alias to the legacy path, or ""
// when it is a real failure.
func engineFallbackReason(err error, a configAuth) string {
	var he *configHTTPError
	if !errors.As(err, &he) {
		return ""
	}
	switch he.Status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Sprintf("the config engine refused the credential from %s (HTTP %d: %s); a config management token (%s) or an owner/admin sign-in uses the engine",
			a.Source, he.Status, he.Message, configTokenEnv)
	case http.StatusNotFound:
		return "the config engine is not available at " + siteBase()
	}
	return ""
}

// renderQualityGateAfterEngine prints what the legacy command printed: the
// stored row, read back through the same /v2 read the legacy path uses. If
// that read is not possible (a config token only), it prints the spec sent.
func renderQualityGateAfterEngine(cmd *cobra.Command, title string, spec map[string]any) error {
	ctx := display.FromCommand(cmd)
	data := map[string]any{"config": spec}
	if client, err := newPackageFirewallConfigClient(cmd); err == nil {
		if resp, err := client.CliQualityGateGet(envForCli()); err == nil {
			data = resp.Data
		}
	}
	if ctx.IsJSON() {
		return ctx.Logger.ResultJSON(data)
	}
	ctx.Logger.Result(renderPackageFirewallResult(ctx, title, data))
	return nil
}

// setQualityGateLegacy is the pre-engine path: POST /v2/cli.quality-gate-config.
func setQualityGateLegacy(cmd *cobra.Command, title string, req vdb.CliQualityGateConfigRequest) error {
	client, err := newPackageFirewallConfigClient(cmd)
	if err != nil {
		return err
	}
	ctx := display.FromCommand(cmd)
	resp, err := client.CliQualityGateConfig(envForCli(), req)
	if err != nil {
		return err
	}
	if ctx.IsJSON() {
		return ctx.Logger.ResultJSON(resp.Data)
	}
	ctx.Logger.Result(renderPackageFirewallResult(ctx, title, resp.Data))
	return nil
}
