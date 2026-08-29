package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/display"
	"github.com/vulnetix/cli/v3/internal/license"
)

// ─────────────────────────────────────────────────────────────────────────
// license_policy.go — the declarative policy and exception surface.
//
// Everything here is reached through runLicensePipeline, per the capability
// owner rule: `license` and `scan --evaluate-licenses` must agree about which
// licences are acceptable and which exceptions cover them, and the way to
// guarantee that is for both to load the same files through the same function.
// ─────────────────────────────────────────────────────────────────────────

// Default discovery paths, relative to the scanned root.
const (
	defaultPolicyPath     = ".vulnetix/license-policy.yaml"
	defaultExceptionsPath = ".vulnetix/license-exceptions.yaml"
)

// addLicenseGovernanceFlags registers --policy-file and --exceptions-file.
//
// Registered on `license` and family-wide on the scan family, because
// `scan --evaluate-licenses` and `license` must reach the same verdict — which
// they only do if both can be pointed at the same policy.
func addLicenseGovernanceFlags(cmd *cobra.Command) {
	if cmd.Flags().Lookup("policy-file") != nil {
		return
	}
	cmd.Flags().String("policy-file", "",
		"Licence policy document (default: <path>/.vulnetix/license-policy.yaml when present)")
	cmd.Flags().String("exceptions-file", "",
		"Approved licence exceptions (default: <path>/.vulnetix/license-exceptions.yaml when present)")
}

// loadLicenseGovernance resolves the policy and exception set for a run.
//
// An explicitly named file that cannot be read is an error: the user asked for
// it, and silently evaluating under the default policy instead would report a
// pass their policy would have failed. A default-path file that is absent is
// not an error — most projects have none.
func loadLicenseGovernance(opts LicenseRunOptions) (*license.Policy, *license.ExceptionSet, error) {
	policy, err := loadPolicyFor(opts.RootPath, opts.PolicyFile)
	if err != nil {
		return nil, nil, err
	}
	exceptions, err := loadExceptionsFor(opts.RootPath, opts.ExceptionsFile)
	if err != nil {
		return nil, nil, err
	}
	return policy, exceptions, nil
}

// loadPolicyFor loads an explicit policy path, or discovers the default one.
func loadPolicyFor(rootPath, explicit string) (*license.Policy, error) {
	if explicit != "" {
		p, err := license.LoadPolicy(explicit)
		if err != nil {
			return nil, fmt.Errorf("--policy-file: %w", err)
		}
		return p, nil
	}
	candidate := filepath.Join(rootPath, defaultPolicyPath)
	if _, err := os.Stat(candidate); err != nil {
		return nil, nil // no policy: the caller falls back to the default
	}
	return license.LoadPolicy(candidate)
}

// loadExceptionsFor loads an explicit exceptions path, or the default one.
func loadExceptionsFor(rootPath, explicit string) (*license.ExceptionSet, error) {
	if explicit != "" {
		s, err := license.LoadExceptions(explicit)
		if err != nil {
			return nil, fmt.Errorf("--exceptions-file: %w", err)
		}
		return s, nil
	}
	candidate := filepath.Join(rootPath, defaultExceptionsPath)
	if _, err := os.Stat(candidate); err != nil {
		return nil, nil
	}
	return license.LoadExceptions(candidate)
}

// ── license policy ──────────────────────────────────────────────────────────

var licensePolicyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage the declarative licence policy",
	Long: `Manage .vulnetix/license-policy.yaml.

A policy classifies licences by category — permissive, weak copyleft, strong
copyleft, proprietary, unknown — and attaches a severity to each. That is how
the decision is actually made, and unlike a flat allow list it stays correct
when a dependency introduces a licence nobody has enumerated yet.

The allow list (--allow / --allow-file) keeps working unchanged. A policy is the
richer form for teams that need per-project thresholds and an auditable
exception process.

Subcommands:
  init      write a recommended starting policy
  show      print the policy in effect, defaults included
  validate  check a policy document for problems`,
	SilenceUsage: true,
}

var licensePolicyInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Write a recommended starting policy",
	Long: `Write a starting licence policy to .vulnetix/license-policy.yaml.

The written policy is deliberately stricter than the built-in default: it flags
proprietary licences, treats AGPL and SSPL as strong copyleft (their obligation
triggers on network use rather than distribution, which the embedded licence
database does not separate out), and takes development and test dependencies out
of scope because they are not shipped.

The built-in default, used when no policy file exists, is the looser one — it
reproduces exactly what this CLI did before policies existed, so an upgrade
never turns a build red for a decision nobody made.

Examples:
  vulnetix license policy init
  vulnetix license policy init --file custom-policy.yaml`,
	RunE:         runLicensePolicyInit,
	SilenceUsage: true,
}

func runLicensePolicyInit(cmd *cobra.Command, args []string) error {
	path, _ := cmd.Flags().GetString("file")
	force, _ := cmd.Flags().GetBool("force")
	rootPath, _ := cmd.Flags().GetString("path")
	if path == "" {
		path = filepath.Join(rootPath, defaultPolicyPath)
	}

	if _, err := os.Stat(path); err == nil && !force {
		return fmt.Errorf("%s already exists; pass --force to overwrite it", path)
	}

	data, err := license.RecommendedPolicy().MarshalYAML()
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}

	term := display.NewTerminal()
	fmt.Printf("%s wrote %s\n", display.CheckMark(term), display.Bold(term, path))
	fmt.Println(display.Muted(term, "Review the severities and scopes before relying on them in CI."))
	return nil
}

var licensePolicyShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Print the licence policy in effect",
	Long: `Print the policy that would be applied, with defaults filled in.

This is the resolved policy, not the file: absent sections are shown with the
values they inherit, so what you read is what the evaluator will do.

Examples:
  vulnetix license policy show
  vulnetix license policy show --project payment-service
  vulnetix license policy show -o json`,
	RunE:         runLicensePolicyShow,
	SilenceUsage: true,
}

func runLicensePolicyShow(cmd *cobra.Command, args []string) error {
	outputFmt, _ := cmd.Flags().GetString("output")
	if err := validateBOMOutput(outputFmt); err != nil {
		return err
	}
	rootPath, _ := cmd.Flags().GetString("path")
	explicit, _ := cmd.Flags().GetString("file")
	project, _ := cmd.Flags().GetString("project")

	policy, err := loadPolicyFor(rootPath, explicit)
	if err != nil {
		return err
	}
	source := explicit
	if source == "" {
		source = filepath.Join(rootPath, defaultPolicyPath)
	}
	if policy == nil {
		policy = license.DefaultPolicy()
		source = "(built-in default — no policy file found)"
	}

	ctx := display.FromCommand(cmd)
	if outputFmt == "json" || ctx.IsJSON() {
		return emitJSON(map[string]any{"source": source, "policy": policy, "project": project})
	}

	term := display.NewTerminal()
	fmt.Println(display.Header(term, "Licence policy"))
	fmt.Println()
	fmt.Printf("Source: %s\n", display.Muted(term, source))
	if project != "" {
		fmt.Printf("Project: %s\n", display.Bold(term, project))
	}
	fmt.Println()

	categories := []license.Category{
		license.CategoryPermissive, license.CategoryPublicDomain,
		license.CategoryWeakCopyleft, license.CategoryStrongCopyleft,
		license.CategoryProprietary, license.CategoryUnknown,
	}
	rows := make([][]string, 0, len(categories))
	for _, cat := range categories {
		sev := policy.SeverityFor(cat, project)
		if sev == "" {
			sev = "none (not a finding)"
		}
		rows = append(rows, []string{string(cat), sev})
	}
	fmt.Print(display.Table(term, []display.Column{
		{Header: "Category", MinWidth: 18},
		{Header: "Severity"},
	}, rows))
	fmt.Print("\n\n")

	fmt.Printf("Unresolved licences: %s\n", display.Bold(term, string(policy.UnknownFor(project))))
	var ignored []string
	for scope := range policy.Scopes {
		if !policy.EvaluatesScope(scope, project) {
			ignored = append(ignored, scope)
		}
	}
	if len(ignored) == 0 {
		fmt.Println("Scopes ignored:      none — every dependency scope is evaluated")
	} else {
		fmt.Printf("Scopes ignored:      %s\n", strings.Join(ignored, ", "))
	}
	return nil
}

var licensePolicyValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Check a licence policy document for problems",
	Long: `Validate a licence policy document.

Checks the apiVersion and kind, that every category named is one the evaluator
knows, that every severity is a severity, and that the unknown-handling and
scope values are in their vocabularies. Exits 1 when the document is invalid.

Examples:
  vulnetix license policy validate
  vulnetix license policy validate --file custom-policy.yaml`,
	RunE:         runLicensePolicyValidate,
	SilenceUsage: true,
}

func runLicensePolicyValidate(cmd *cobra.Command, args []string) error {
	rootPath, _ := cmd.Flags().GetString("path")
	explicit, _ := cmd.Flags().GetString("file")

	path := explicit
	if path == "" {
		path = filepath.Join(rootPath, defaultPolicyPath)
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("no policy at %s; run 'vulnetix license policy init' to create one", path)
	}
	if _, err := license.LoadPolicy(path); err != nil {
		return err
	}

	term := display.NewTerminal()
	fmt.Printf("%s %s is a valid licence policy\n", display.CheckMark(term), display.Bold(term, path))
	return nil
}

// ── license exceptions ──────────────────────────────────────────────────────

var licenseExceptionsCmd = &cobra.Command{
	Use:   "exceptions",
	Short: "Manage approved licence exceptions",
	Long: `Manage .vulnetix/license-exceptions.yaml.

Every real policy has exceptions — a vendored MPL-2.0 utility counsel signed
off, a GPL build tool that never ships. What matters is whether the exception is
recorded or whether somebody quietly widened the allow list. So an exception
carries who approved it, when, on what grounds and until when.

An expired exception stops applying, and the finding says so rather than
reappearing unexplained. Exempted findings are retained and badged, never
dropped: a violation count that fell because somebody wrote an exception is a
different fact from one that fell because the dependency was removed.

Subcommands:
  ls     list exceptions and their status
  check  report exceptions expiring soon
  add    append an exception`,
	SilenceUsage: true,
}

var licenseExceptionsLsCmd = &cobra.Command{
	Use:   "ls",
	Short: "List approved licence exceptions",
	Long: `List the exceptions in .vulnetix/license-exceptions.yaml.

Shows what each exception covers, who approved it, and whether it is still
valid. Expired exceptions are listed and marked, because an exception that has
lapsed is the reason a finding came back.

Examples:
  vulnetix license exceptions ls
  vulnetix license exceptions ls -o json`,
	RunE:         runLicenseExceptionsLs,
	SilenceUsage: true,
}

func runLicenseExceptionsLs(cmd *cobra.Command, args []string) error {
	outputFmt, _ := cmd.Flags().GetString("output")
	if err := validateBOMOutput(outputFmt); err != nil {
		return err
	}
	set, path, err := requireExceptions(cmd)
	if err != nil {
		return err
	}

	now := time.Now()
	type row struct {
		Kind     string            `json:"kind"`
		Match    string            `json:"match"`
		License  string            `json:"license,omitempty"`
		Status   string            `json:"status"`
		Approver string            `json:"approver,omitempty"`
		Expires  string            `json:"expires,omitempty"`
		Reason   string            `json:"reason"`
		Projects []string          `json:"projects,omitempty"`
		Raw      license.Exception `json:"-"`
	}
	var rows []row
	add := func(e license.Exception, kind, match, lic string) {
		status := "active"
		if e.Expired(now) {
			status = "EXPIRED"
		}
		rows = append(rows, row{
			Kind: kind, Match: match, License: lic, Status: status,
			Approver: e.Approver, Expires: e.Expires, Reason: e.Reason,
			Projects: e.Projects, Raw: e,
		})
	}
	for _, b := range set.Blanket {
		add(b.Exception, "blanket", b.License, b.License)
	}
	for _, p := range set.Packages {
		add(p.Exception, "package", preferLabel(p.Purl, p.Name), p.License)
	}

	ctx := display.FromCommand(cmd)
	if outputFmt == "json" || ctx.IsJSON() {
		return emitJSON(map[string]any{"source": path, "exceptions": rows})
	}

	term := display.NewTerminal()
	fmt.Println(display.Header(term, "Licence exceptions"))
	fmt.Println()
	if len(rows) == 0 {
		fmt.Println(display.Muted(term, "No exceptions recorded."))
		return nil
	}
	table := make([][]string, 0, len(rows))
	for _, r := range rows {
		table = append(table, []string{
			r.Status, r.Kind, r.Match, orDash(r.License),
			orDash(r.Approver), orDash(r.Expires), r.Reason,
		})
	}
	fmt.Print(display.Table(term, []display.Column{
		{Header: "Status", MinWidth: 8},
		{Header: "Kind", MinWidth: 8},
		{Header: "Covers", MinWidth: 24, MaxWidth: 40},
		{Header: "Licence", MinWidth: 12},
		{Header: "Approver", MinWidth: 16, MaxWidth: 24},
		{Header: "Expires", MinWidth: 11},
		{Header: "Reason"},
	}, table))
	fmt.Print("\n\n")
	fmt.Println(display.Muted(term, fmt.Sprintf("%d exception(s) in %s", len(rows), path)))
	return nil
}

var licenseExceptionsCheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Report licence exceptions expiring soon",
	Long: `Report exceptions that have lapsed or will lapse soon.

An exception that expires without anyone noticing turns into a surprise red
build. Running this on a schedule turns the expiry into a review cadence rather
than a trap.

Exits 1 when any exception has already expired, so it can be a scheduled CI
check rather than something somebody has to remember.

Examples:
  vulnetix license exceptions check
  vulnetix license exceptions check --expiring-within 90d
  vulnetix license exceptions check -o json`,
	RunE:         runLicenseExceptionsCheck,
	SilenceUsage: true,
}

func runLicenseExceptionsCheck(cmd *cobra.Command, args []string) error {
	outputFmt, _ := cmd.Flags().GetString("output")
	if err := validateBOMOutput(outputFmt); err != nil {
		return err
	}
	withinRaw, _ := cmd.Flags().GetString("expiring-within")
	within, err := parseDayDuration(withinRaw)
	if err != nil {
		return err
	}
	set, path, err := requireExceptions(cmd)
	if err != nil {
		return err
	}

	now := time.Now()
	expiring := set.Expiring(now, within)

	var expired int
	for _, a := range expiring {
		if a.Expired {
			expired++
		}
	}

	ctx := display.FromCommand(cmd)
	if outputFmt == "json" || ctx.IsJSON() {
		if err := emitJSON(map[string]any{
			"source": path, "within": withinRaw,
			"expiring": expiring, "expired": expired,
		}); err != nil {
			return err
		}
	} else {
		term := display.NewTerminal()
		fmt.Println(display.Header(term, "Licence exception review"))
		fmt.Println()
		if len(expiring) == 0 {
			fmt.Printf("%s No exceptions lapse within %s.\n", display.CheckMark(term), withinRaw)
		} else {
			rows := make([][]string, 0, len(expiring))
			for _, a := range expiring {
				status := "expiring"
				if a.Expired {
					status = "EXPIRED"
				}
				rows = append(rows, []string{
					status, a.Exception.Expires, a.Kind, a.Match,
					orDash(a.Exception.Approver), a.Exception.Reason,
				})
			}
			fmt.Print(display.Table(term, []display.Column{
				{Header: "Status", MinWidth: 9},
				{Header: "Expires", MinWidth: 11},
				{Header: "Kind", MinWidth: 8},
				{Header: "Covers", MinWidth: 24, MaxWidth: 40},
				{Header: "Approver", MinWidth: 16, MaxWidth: 24},
				{Header: "Reason"},
			}, rows))
			fmt.Print("\n\n")
		}
	}

	if expired > 0 {
		return &bomGateError{
			gate:    "license-exceptions",
			message: fmt.Sprintf("%d licence exception(s) have expired and no longer apply", expired),
		}
	}
	return nil
}

var licenseExceptionsAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Append a licence exception",
	Long: `Append an exception to .vulnetix/license-exceptions.yaml.

Either --license (a blanket exception covering that licence wherever it appears)
or one of --purl / --name (an exception covering one package). --reason is
required: an exception nobody can explain is indistinguishable from a mistake.

Examples:
  vulnetix license exceptions add --license MPL-2.0 \
    --reason "file-level copyleft, unmodified" --approver security@example.com

  vulnetix license exceptions add --purl 'pkg:golang/github.com/hashicorp/*' \
    --license MPL-2.0 --reason "vendored, unmodified" --expires 2027-08-01`,
	RunE:         runLicenseExceptionsAdd,
	SilenceUsage: true,
}

func runLicenseExceptionsAdd(cmd *cobra.Command, args []string) error {
	rootPath, _ := cmd.Flags().GetString("path")
	explicit, _ := cmd.Flags().GetString("file")
	licenseID, _ := cmd.Flags().GetString("license")
	purl, _ := cmd.Flags().GetString("purl")
	name, _ := cmd.Flags().GetString("name")
	reason, _ := cmd.Flags().GetString("reason")
	approver, _ := cmd.Flags().GetString("approver")
	scope, _ := cmd.Flags().GetString("scope")
	expires, _ := cmd.Flags().GetString("expires")
	id, _ := cmd.Flags().GetString("id")
	projects, _ := cmd.Flags().GetStringArray("project")

	if reason == "" {
		return fmt.Errorf("--reason is required: an exception nobody can explain is indistinguishable from a mistake")
	}
	if licenseID == "" && purl == "" && name == "" {
		return fmt.Errorf("pass --license for a blanket exception, or --purl / --name for a package exception")
	}

	path := explicit
	if path == "" {
		path = filepath.Join(rootPath, defaultExceptionsPath)
	}

	set := &license.ExceptionSet{APIVersion: license.ExceptionsAPIVersion, Kind: license.ExceptionsKind}
	if _, err := os.Stat(path); err == nil {
		existing, err := license.LoadExceptions(path)
		if err != nil {
			return err
		}
		set = existing
	}

	exception := license.Exception{
		ID: id, Reason: reason, Scope: scope, Approver: approver,
		ApprovedDate: time.Now().UTC().Format("2006-01-02"),
		Expires:      expires, Projects: projects,
	}
	if expires != "" {
		if _, err := exception.ExpiresAt(); err != nil {
			return err
		}
	}

	switch {
	case purl != "" || name != "":
		set.Packages = append(set.Packages, license.PackageException{
			Purl: purl, Name: name, License: licenseID, Exception: exception,
		})
	default:
		set.Blanket = append(set.Blanket, license.BlanketException{
			License: licenseID, Exception: exception,
		})
	}

	// Validate before writing, so a malformed entry is rejected rather than
	// persisted and then rejected on every subsequent run.
	if err := set.Validate(); err != nil {
		return err
	}
	data, err := set.MarshalYAML()
	if err != nil {
		return err
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}

	term := display.NewTerminal()
	fmt.Printf("%s exception added to %s\n", display.CheckMark(term), display.Bold(term, path))
	return nil
}

// requireExceptions loads the exception set, erroring when there is none.
func requireExceptions(cmd *cobra.Command) (*license.ExceptionSet, string, error) {
	rootPath, _ := cmd.Flags().GetString("path")
	explicit, _ := cmd.Flags().GetString("file")

	path := explicit
	if path == "" {
		path = filepath.Join(rootPath, defaultExceptionsPath)
	}
	if _, err := os.Stat(path); err != nil {
		return nil, path, fmt.Errorf("no exceptions at %s; add one with 'vulnetix license exceptions add'", path)
	}
	set, err := license.LoadExceptions(path)
	if err != nil {
		return nil, path, err
	}
	return set, path, nil
}

// licenseFindingStatus renders a finding's exemption state for the table.
func licenseFindingStatus(f license.Finding) string {
	switch {
	case f.Exempted:
		return "exempted"
	case f.ExemptionExpired:
		return "EXPIRED"
	default:
		return "open"
	}
}

// parseDayDuration parses a "30d" / "90d" / "12h" window.
//
// Days are the natural unit for an exception review cadence, and
// time.ParseDuration does not accept them.
func parseDayDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 30 * 24 * time.Hour, nil
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("--expiring-within: %q is not a number of days", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("--expiring-within: %q (expected e.g. 30d, 90d or 48h)", s)
	}
	return d, nil
}

func init() {
	licensePolicyCmd.AddCommand(licensePolicyInitCmd, licensePolicyShowCmd, licensePolicyValidateCmd)
	licenseExceptionsCmd.AddCommand(licenseExceptionsLsCmd, licenseExceptionsCheckCmd, licenseExceptionsAddCmd)
	licenseCmd.AddCommand(licensePolicyCmd, licenseExceptionsCmd)

	// Every subcommand resolves its file the same way: an explicit --file, or
	// the default path under --path.
	for _, c := range []*cobra.Command{
		licensePolicyInitCmd, licensePolicyShowCmd, licensePolicyValidateCmd,
		licenseExceptionsLsCmd, licenseExceptionsCheckCmd, licenseExceptionsAddCmd,
	} {
		c.Flags().String("path", ".", "Project root the default file path is relative to")
		c.Flags().String("file", "", "Explicit document path")
	}
	for _, c := range []*cobra.Command{
		licensePolicyShowCmd, licenseExceptionsLsCmd, licenseExceptionsCheckCmd,
	} {
		c.Flags().StringP("output", "o", "pretty", "Output format: pretty (alias: table), json")
	}

	licensePolicyInitCmd.Flags().Bool("force", false, "Overwrite an existing policy")
	licensePolicyShowCmd.Flags().String("project", "", "Show the policy as it applies to this project")

	licenseExceptionsCheckCmd.Flags().String("expiring-within", "30d",
		"Report exceptions lapsing within this window (e.g. 30d, 90d)")

	licenseExceptionsAddCmd.Flags().String("license", "", "SPDX id for a blanket exception, or to narrow a package exception")
	licenseExceptionsAddCmd.Flags().String("purl", "", "Package URL to exempt; '*' is a wildcard")
	licenseExceptionsAddCmd.Flags().String("name", "", "Package name to exempt")
	licenseExceptionsAddCmd.Flags().String("reason", "", "Why the exception exists (required)")
	licenseExceptionsAddCmd.Flags().String("approver", "", "Who approved it")
	licenseExceptionsAddCmd.Flags().String("scope", "", "What the approval is scoped to, e.g. 'vendored, unmodified'")
	licenseExceptionsAddCmd.Flags().String("expires", "", "When it lapses, as YYYY-MM-DD")
	licenseExceptionsAddCmd.Flags().String("id", "", "Stable identifier for referring to it in a report")
	licenseExceptionsAddCmd.Flags().StringArray("project", nil, "Limit the exception to a project (repeatable)")
}
