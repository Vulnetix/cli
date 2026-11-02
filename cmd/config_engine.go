package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/vulnetix/cli/v3/internal/gitctx"
	"github.com/vulnetix/cli/v3/internal/platformiac"
)

// Config-as-code against the server: plan, apply and export. Documents are
// checked offline first (config_documents.go), secrets named by valueFrom are
// read on this machine, and only then does anything go to the engine. The
// engine plans and applies; the CLI never decides what changes.

// Errors that name their exit code (exit_codes.go).

// configPlanBlockedError: the plan has blocking conditions, so it cannot be
// applied as written. Exit 3.
type configPlanBlockedError struct{ n int }

func (e *configPlanBlockedError) Error() string {
	return fmt.Sprintf("the plan has %s; nothing was applied", pluralise("blocking condition", e.n))
}
func (e *configPlanBlockedError) ExitCode() int { return ExitPlanBlocked }

// configUsageError: a flag or environment problem found before any request.
// Exit 2.
type configUsageError struct{ err error }

func (e *configUsageError) Error() string { return e.err.Error() }
func (e *configUsageError) Unwrap() error { return e.err }
func (e *configUsageError) ExitCode() int { return ExitUsage }

// configApplyIncompleteError is an apply that wrote only part of its plan: the
// server answered 207, or an object ended in phase Failed. The rest was applied
// and stays applied, so it is not ExitPlanBlocked (nothing written); it is a
// failure of the step. Exit 1.
type configApplyIncompleteError struct {
	failed, counted int
	partial         bool
}

func (e *configApplyIncompleteError) Error() string {
	n := e.failed
	if n == 0 {
		n = e.counted
	}
	if n == 0 {
		return "applied only in part: the config engine answered 207; plan again to see what is left"
	}
	return fmt.Sprintf("applied only in part: %d object(s) failed to write; plan again to see what is left", n)
}
func (e *configApplyIncompleteError) ExitCode() int { return ExitFailure }

func configUsage(format string, a ...any) error {
	return &configUsageError{err: fmt.Errorf(format, a...)}
}

// configStdinIsTerminal is replaced by tests.
var configStdinIsTerminal = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }

// configInput is what plan and apply send: the decoded documents with their
// secrets resolved, and the secret values so output can be masked.
type configInput struct {
	Docs    []configDocument
	Values  []any
	secrets []string
}

// loadConfigInput reads and validates the documents named by -f, and with
// resolve reads the secrets their valueFrom references name.
func loadConfigInput(cmd *cobra.Command, files []string, resolve bool) (*configInput, error) {
	// The well-known files (.vulnetix/ai-firewall.yaml and the licence files)
	// are validated by config validate but not yet planned: sending them to
	// the engine is the v4 change. Name one with -f to plan it now.
	docs, _, err := discoverConfigDocuments(cmd, files, false)
	if err != nil {
		return nil, err
	}
	if len(docs) == 0 {
		// Planning nothing with --prune would delete everything this manager
		// owns, so a missing directory is never read as "declare nothing".
		return nil, configUsage("no config documents (looked in %s); pass -f", defaultConfigDir)
	}
	problems, err := validateConfigDocuments(docs)
	if err != nil {
		return nil, err
	}
	if len(problems) > 0 {
		for _, p := range problems {
			fmt.Fprintln(cmd.ErrOrStderr(), p)
		}
		return nil, fmt.Errorf("%d of %d documents invalid; nothing was sent", len(problems), len(docs))
	}
	// Local kinds (LicenseExceptions) are validated here and never sent: the
	// engine has no adapter for them yet.
	send := docs[:0:0]
	for _, d := range docs {
		if platformiac.IsLocal(d.Kind) {
			fmt.Fprintf(cmd.ErrOrStderr(), "note: %s (document %d) is a %s, which is validated locally and not sent to the config engine\n", d.Path, d.Index, d.Kind)
			continue
		}
		send = append(send, d)
	}
	if len(send) == 0 {
		return nil, configUsage("nothing to send: every document is a kind the engine does not take yet")
	}
	in := &configInput{Docs: send}
	for _, d := range send {
		if !resolve {
			in.Values = append(in.Values, d.Value)
			continue
		}
		v, secrets, err := resolveValueFrom(d.Value, "")
		if err != nil {
			return nil, fmt.Errorf("%s (document %d): %w", d.Path, d.Index, err)
		}
		in.Values = append(in.Values, v)
		in.secrets = append(in.secrets, secrets...)
	}
	return in, nil
}

// resolveValueFrom replaces every {valueFrom: {env: X}} or {valueFrom: {file:
// p}} in v with the value it names, read on this machine. The engine never
// sees the reference, only the value, and exports the field back as a
// valueFrom.env placeholder. The values are returned so output can mask them;
// errors name the field and the source, never the value.
func resolveValueFrom(v any, path string) (any, []string, error) {
	switch t := v.(type) {
	case map[string]any:
		if ref, ok := t["valueFrom"].(map[string]any); ok && len(t) == 1 {
			val, err := readValueFrom(ref)
			if err != nil {
				return nil, nil, fmt.Errorf("%s: %w", strings.TrimPrefix(path, "."), err)
			}
			return val, []string{val}, nil
		}
		out := make(map[string]any, len(t))
		var secrets []string
		for k, e := range t {
			r, s, err := resolveValueFrom(e, path+"."+k)
			if err != nil {
				return nil, nil, err
			}
			out[k] = r
			secrets = append(secrets, s...)
		}
		return out, secrets, nil
	case []any:
		out := make([]any, len(t))
		var secrets []string
		for i, e := range t {
			r, s, err := resolveValueFrom(e, fmt.Sprintf("%s[%d]", path, i))
			if err != nil {
				return nil, nil, err
			}
			out[i] = r
			secrets = append(secrets, s...)
		}
		return out, secrets, nil
	default:
		return v, nil, nil
	}
}

func readValueFrom(ref map[string]any) (string, error) {
	if name, ok := ref["env"].(string); ok {
		val, set := os.LookupEnv(name)
		if !set || val == "" {
			return "", fmt.Errorf("valueFrom.env: %s is not set", name)
		}
		return val, nil
	}
	if p, ok := ref["file"].(string); ok {
		// Relative paths are relative to the working directory, as for -f.
		b, err := os.ReadFile(expandHome(p))
		if err != nil {
			return "", fmt.Errorf("valueFrom.file: %w", err)
		}
		val := strings.TrimRight(string(b), "\r\n")
		if val == "" {
			return "", fmt.Errorf("valueFrom.file: %s is empty", p)
		}
		return val, nil
	}
	return "", errors.New("valueFrom needs env or file")
}

// mask hides every resolved secret in s. The engine already redacts the
// fields its kinds declare secret; this covers a kind that forgot to.
func (in *configInput) mask(s string) string {
	if in == nil {
		return s
	}
	for _, sec := range in.secrets {
		// Very short values would mask unrelated text and say little anyway.
		if len(sec) >= 4 {
			s = strings.ReplaceAll(s, sec, "(secret)")
		}
	}
	return s
}

// detectConfigManager returns the manager for this run: --manager, else
// gitops:<owner/repo> from GITHUB_REPOSITORY (Actions) or the repository's
// GitHub remote. The repo is lowercased because GitHub names are not case
// sensitive but the engine compares managers exactly: a checkout whose remote
// says vulnetix/cli and an Actions run that says Vulnetix/cli must be the same
// manager, or each would block the other with managed_by_other.
func detectConfigManager(flag, dir string) (string, error) {
	if m := strings.TrimSpace(flag); m != "" {
		return m, nil
	}
	if repo := strings.TrimSpace(os.Getenv("GITHUB_REPOSITORY")); repo != "" {
		return "gitops:" + strings.ToLower(repo), nil
	}
	if g := gitctx.Collect(dir); g != nil {
		for _, u := range g.RemoteURLs {
			if repo := githubRepoFromRemote(u); repo != "" {
				return "gitops:" + strings.ToLower(repo), nil
			}
		}
	}
	return "", configUsage("--manager is required outside a git repository with a GitHub remote (terraform, console or gitops:<owner/repo>)")
}

// githubRepoFromRemote returns owner/repo for a github.com remote URL.
func githubRepoFromRemote(raw string) string {
	s := strings.TrimSuffix(strings.TrimSpace(raw), "/")
	s = strings.TrimSuffix(s, ".git")
	switch {
	case strings.HasPrefix(s, "git@github.com:"):
		s = strings.TrimPrefix(s, "git@github.com:")
	default:
		u, err := url.Parse(s)
		if err != nil || !strings.EqualFold(u.Hostname(), "github.com") {
			return ""
		}
		s = strings.TrimPrefix(u.Path, "/")
	}
	parts := strings.Split(s, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	return parts[0] + "/" + parts[1]
}

// configSourceRef is the commit the documents came from, recorded with each
// applied object.
func configSourceRef(dir string) string {
	if sha := strings.TrimSpace(os.Getenv("GITHUB_SHA")); sha != "" {
		return sha
	}
	if g := gitctx.Collect(dir); g != nil {
		return g.CurrentCommit
	}
	return ""
}

// checkConfigOrg refuses documents whose metadata.org names another tenant,
// as ai-firewall apply does. The engine blocks them too (org_mismatch); this
// check is the CLI's own, so a file meant for one org is never applied to
// another even by a server that missed it.
func checkConfigOrg(docs []configDocument, tenant string) error {
	if tenant == "" {
		return nil
	}
	for _, d := range docs {
		m, _ := d.Value.(map[string]any)
		md, _ := m["metadata"].(map[string]any)
		org, _ := md["org"].(string)
		if org != "" && !strings.EqualFold(org, tenant) {
			return fmt.Errorf("%s (document %d) declares metadata.org %s, but you are authenticated to %s; refusing", d.Path, d.Index, org, tenant)
		}
	}
	return nil
}

// configCommon holds the flags plan and apply share.
type configCommon struct {
	files   []string
	manager string
	prune   bool
	token   string
}

func (c *configCommon) bind(cmd *cobra.Command) {
	cmd.Flags().StringArrayVarP(&c.files, "file", "f", nil, "file or directory of documents (repeatable; - for stdin; default .vulnetix/config)")
	cmd.Flags().StringVar(&c.manager, "manager", "", "who declares these documents: terraform, console or gitops:<owner/repo> (default: gitops:<this GitHub repo>)")
	cmd.Flags().BoolVar(&c.prune, "prune", false, "delete objects this manager owns that the documents no longer declare")
	cmd.Flags().StringVar(&c.token, "token", "", "config management token (default: $"+configTokenEnv+", then the stored credential)")
}

// configSession is one plan (and maybe apply) against the engine.
type configSession struct {
	in     *configInput
	client *configEngineClient
	req    configRequest
}

func newConfigSession(cmd *cobra.Command, c *configCommon) (*configSession, error) {
	manager, err := detectConfigManager(c.manager, ".")
	if err != nil {
		return nil, err
	}
	in, err := loadConfigInput(cmd, c.files, true)
	if err != nil {
		return nil, err
	}
	a, err := resolveConfigAuth(c.token)
	if err != nil {
		return nil, configUsage("%v", err)
	}
	return &configSession{
		in:     in,
		client: newConfigEngineClient(a),
		req:    configRequest{Manager: manager, Prune: c.prune, SourceRef: configSourceRef("."), Documents: in.Values},
	}, nil
}

// plan runs the plan and the org guard.
func (s *configSession) plan(ctx context.Context) (*configPlan, []byte, error) {
	p, raw, err := s.client.Plan(ctx, s.req)
	if err != nil {
		return nil, nil, explainConfigAuth(err, s.client.Auth, ownerKindHint(err, s.in.Docs))
	}
	if err := checkConfigOrg(s.in.Docs, p.Tenant); err != nil {
		return nil, nil, err
	}
	return p, raw, nil
}

// explainConfigAuth adds what to do when the engine refuses the credential.
func explainConfigAuth(err error, a configAuth, hints ...string) error {
	var he *configHTTPError
	if !errors.As(err, &he) {
		return err
	}
	switch he.Status {
	case 401:
		return fmt.Errorf("%w (credential from %s was not accepted; use a config management token via --token or %s)", err, a.Source, configTokenEnv)
	case 403:
		msg := fmt.Errorf("%w (credential from %s is not an owner or admin, or the token does not allow this kind)", err, a.Source)
		for _, h := range hints {
			if h != "" {
				msg = fmt.Errorf("%w; %s", msg, h)
			}
		}
		return msg
	}
	return err
}

func newConfigPlanCommand() *cobra.Command {
	var (
		c      configCommon
		output string
	)
	cmd := &cobra.Command{
		Use:   "plan",
		Short: "Show what applying config-as-code documents would change",
		Long: `Plan vulnetix.com/v1 config documents against the organization's live state.

Reads every .yaml, .yml and .json file under .vulnetix/config/ (recursively),
or the files and directories given with -f, validates them offline, resolves
valueFrom secrets on this machine, and asks the config engine what applying
them would do: create, update, delete or no change per object, with a field
diff and any blocking conditions. Nothing is changed.

--manager names who declares the documents. Inside a git repository with a
GitHub remote it defaults to gitops:<owner/repo>. An object owned by another
manager cannot be changed, and --prune only deletes objects this manager owns.

Exit status: 0 when the plan can be applied, 3 when it has blocking
conditions, 2 for a usage error, 1 for anything else.`,
		Example: `  vulnetix config plan
  vulnetix config plan -f .vulnetix/config/quality-gate.yaml -o json
  vulnetix config plan --manager gitops:acme/platform-config --prune`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if output != "text" && output != "json" {
				return configUsage("-o must be text or json")
			}
			s, err := newConfigSession(cmd, &c)
			if err != nil {
				return err
			}
			p, raw, err := s.plan(cmd.Context())
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if output == "json" {
				if err := writeConfigJSON(out, raw, s.in); err != nil {
					return err
				}
			} else {
				fmt.Fprint(out, s.in.mask(renderConfigPlan(p)))
			}
			if len(p.Blocking) > 0 {
				return &configPlanBlockedError{n: len(p.Blocking)}
			}
			return nil
		},
	}
	c.bind(cmd)
	cmd.Flags().StringVarP(&output, "output", "o", "text", "output format: text or json")
	_ = cmd.RegisterFlagCompletionFunc("output", cobra.FixedCompletions([]string{"text", "json"}, cobra.ShellCompDirectiveNoFileComp))
	return cmd
}

func newConfigApplyCommand() *cobra.Command {
	var (
		c           configCommon
		autoApprove bool
		planHash    string
	)
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Apply config-as-code documents to the organization",
		Long: `Plan the documents (as 'vulnetix config plan' does), show the plan, ask
for confirmation, then apply exactly that plan.

The engine applies a plan only while its planHash still matches the live
state, in one transaction. If anything changed since the plan was made, apply
refuses (HTTP 409) and nothing is written; plan again and review.

Confirmation is skipped with --auto-approve, or with --plan-hash naming the
plan you reviewed (from 'vulnetix config plan -o json'); apply then refuses if
the fresh plan has a different hash. Without a terminal one of the two is
required.

Exit status: 0 when applied (or nothing to do), 3 when the plan has blocking
conditions, 2 for a usage error, 1 for anything else, including a 409 and an
apply the server answered with 207: everything was applied except the objects
whose write failed (phase Failed), which are listed. Plan again to see what is
left.`,
		Example: `  vulnetix config apply
  vulnetix config apply --auto-approve
  vulnetix config apply --plan-hash 3f1c...`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			s, err := newConfigSession(cmd, &c)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			p, _, err := s.plan(cmd.Context())
			if err != nil {
				return err
			}
			fmt.Fprint(out, s.in.mask(renderConfigPlan(p)))
			if len(p.Blocking) > 0 {
				return &configPlanBlockedError{n: len(p.Blocking)}
			}
			if planHash != "" && planHash != p.PlanHash {
				return fmt.Errorf("the plan changed since the one you reviewed (%s, now %s); plan again and review", planHash, p.PlanHash)
			}
			if !p.needsApply() {
				fmt.Fprintln(out, "Nothing to apply.")
				return nil
			}
			if planHash == "" && !autoApprove {
				if err := confirmConfigApply(cmd, c.files); err != nil {
					return err
				}
			}
			req := s.req
			req.PlanHash = p.PlanHash
			res, err := s.client.Apply(cmd.Context(), req)
			if err != nil {
				return explainConfigApplyError(err, s.client.Auth)
			}
			fmt.Fprint(out, renderConfigApplyResult(res))
			if res.incomplete() {
				return &configApplyIncompleteError{failed: len(res.failedItems()), partial: res.Partial, counted: res.Failed}
			}
			return nil
		},
	}
	c.bind(cmd)
	cmd.Flags().BoolVar(&autoApprove, "auto-approve", false, "apply without asking")
	cmd.Flags().StringVar(&planHash, "plan-hash", "", "apply only if the plan still has this planHash (implies approval)")
	return cmd
}

// confirmConfigApply asks on the terminal. Documents read from stdin leave no
// terminal to ask on, so they need --auto-approve as well.
func confirmConfigApply(cmd *cobra.Command, files []string) error {
	for _, f := range files {
		if f == "-" {
			return configUsage("documents were read from stdin, so there is no terminal to confirm on; pass --auto-approve or --plan-hash")
		}
	}
	if !configStdinIsTerminal() {
		return configUsage("not a terminal; pass --auto-approve or --plan-hash to apply without confirmation")
	}
	fmt.Fprint(cmd.ErrOrStderr(), "\nApply this plan? Only 'yes' is accepted: ")
	line, _ := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
	if strings.TrimSpace(line) != "yes" {
		return errors.New("apply cancelled")
	}
	return nil
}

// explainConfigApplyError turns the engine's refusals into what to do next.
func explainConfigApplyError(err error, a configAuth) error {
	var he *configHTTPError
	if errors.As(err, &he) {
		switch he.Status {
		case 409:
			msg := "the configuration changed after this plan was made (someone applied or edited it), so nothing was applied; run 'vulnetix config plan' again and review"
			if p := planFromHTTPError(err); p != nil {
				msg += fmt.Sprintf(" (the fresh plan: %s)", summaryLine(p.Summary))
			}
			return errors.New(msg)
		case 422:
			n := 1
			if p := planFromHTTPError(err); p != nil && len(p.Blocking) > 0 {
				n = len(p.Blocking)
			}
			return &configPlanBlockedError{n: n}
		}
	}
	return explainConfigAuth(err, a)
}

var configActionMarks = map[string]string{"create": "+", "update": "~", "delete": "-", "noop": "="}

// renderConfigPlan formats a plan for people.
func renderConfigPlan(p *configPlan) string {
	var b strings.Builder
	prune := "off"
	if p.Prune {
		prune = "on"
	}
	fmt.Fprintf(&b, "Plan for %s (manager %s, prune %s)\n\n", p.Tenant, p.Manager, prune)
	if len(p.Items) == 0 {
		b.WriteString("  No objects.\n")
	}
	for _, it := range p.Items {
		mark := configActionMarks[it.Action]
		if mark == "" {
			mark = "?"
		}
		var notes []string
		if it.Adopt {
			notes = append(notes, "adopt: no manager owns it yet")
		}
		if it.Drift {
			notes = append(notes, "drift: changed since its manager last applied it")
		}
		if it.Manager != "" && it.Manager != p.Manager {
			notes = append(notes, "managed by "+it.Manager)
		}
		line := fmt.Sprintf("  %s %s/%s  %s", mark, it.Kind, it.Name, it.Action)
		if len(notes) > 0 {
			line += " (" + strings.Join(notes, "; ") + ")"
		}
		b.WriteString(line + "\n")
		for _, ch := range it.Changes {
			fmt.Fprintf(&b, "      %s: %s -> %s\n", ch.Path, configValue(ch.From), configValue(ch.To))
		}
	}
	writeConds := func(title, mark string, cs []configCondition) {
		if len(cs) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n%s:\n", title)
		for _, c := range cs {
			where := ""
			if c.Kind != "" {
				where = " " + c.Kind + "/" + c.Name
			}
			fmt.Fprintf(&b, "  %s [%s]%s: %s\n", mark, c.Code, where, c.Message)
		}
	}
	writeConds("Blocking", "!", p.Blocking)
	writeConds("Warnings", "*", p.Warnings)
	fmt.Fprintf(&b, "\n%s\nPlan hash: %s\n", summaryLine(p.Summary), p.PlanHash)
	return b.String()
}

func summaryLine(s configSummary) string {
	return fmt.Sprintf("%d to create, %d to update, %d to delete, %d unchanged", s.Create, s.Update, s.Delete, s.Noop)
}

// configValue prints a diff value compactly; an absent value is (unset).
func configValue(v any) string {
	if v == nil {
		return "(unset)"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

func renderConfigApplyResult(r *configApplyResult) string {
	var b strings.Builder
	b.WriteString("\nApplied:\n")
	for _, it := range r.Items {
		fmt.Fprintf(&b, "  %s %s/%s  %s\n", configActionMarks[it.Action], it.Kind, it.Name, it.Status.Phase)
		if it.Status.Message != "" {
			fmt.Fprintf(&b, "      %s\n", it.Status.Message)
		}
	}
	fmt.Fprintf(&b, "\n%s\n", summaryLine(r.Summary))
	return b.String()
}

// writeConfigJSON re-indents the server's JSON, masked.
func writeConfigJSON(w io.Writer, raw []byte, in *configInput) error {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, in.mask(string(b)))
	return err
}

func newConfigExportCommand() *cobra.Command {
	var (
		kind, name, manager, format, outFile, token string
		files                                       []string
	)
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Write the organization's configuration as code",
		Long: `Export the organization's live configuration from the config engine.

  yaml  vulnetix.com/v1 documents for .vulnetix/config/
  hcl   Terraform resources with import blocks, so adopting shows no changes
  sh    a bash script that runs 'vulnetix config apply -f -' with the YAML inline

Secrets are never exported; they come back as valueFrom.env placeholders.
With -f the documents given are rendered instead of the live state (a draft),
which converts YAML to HCL or a script without applying anything.`,
		Example: `  vulnetix config export > .vulnetix/config/all.yaml
  vulnetix config export --kind QualityGate --format hcl -o quality-gate.tf
  vulnetix config export -f .vulnetix/config --format sh`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			switch format {
			case "yaml", "hcl", "sh":
			default:
				return configUsage("--format must be yaml, hcl or sh")
			}
			a, err := resolveConfigAuth(token)
			if err != nil {
				return configUsage("%v", err)
			}
			q := url.Values{"format": {format}}
			var draft []any
			if len(files) > 0 {
				// A draft is rendered into a file, so its valueFrom references
				// stay references: nothing secret is read or sent.
				in, err := loadConfigInput(cmd, files, false)
				if err != nil {
					return err
				}
				draft = in.Values
			} else {
				for k, v := range map[string]string{"kind": kind, "name": name, "manager": manager} {
					if v != "" {
						q.Set(k, v)
					}
				}
			}
			body, err := newConfigEngineClient(a).Export(cmd.Context(), q, draft)
			if err != nil {
				hint := ""
				if ownerOnlyKinds[kind] {
					hint = kind + " can only be exported with an owner token"
				}
				return explainConfigAuth(err, a, hint)
			}
			if outFile == "" || outFile == "-" {
				_, err = cmd.OutOrStdout().Write(body)
				return err
			}
			if dir := filepath.Dir(outFile); dir != "." {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					return err
				}
			}
			if err := os.WriteFile(outFile, body, 0o644); err != nil {
				return err
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "wrote %s\n", outFile)
			return nil
		},
	}
	cmd.Flags().StringVar(&kind, "kind", "", "only this kind")
	cmd.Flags().StringVar(&name, "name", "", "only the object with this metadata.name")
	cmd.Flags().StringVar(&manager, "manager", "", "only objects owned by this manager")
	cmd.Flags().StringVar(&format, "format", "yaml", "yaml, hcl or sh")
	cmd.Flags().StringVarP(&outFile, "output", "o", "", "write to this file instead of standard output")
	cmd.Flags().StringArrayVarP(&files, "file", "f", nil, "render these documents (a draft) instead of the live state")
	cmd.Flags().StringVar(&token, "token", "", "config management token (default: $"+configTokenEnv+", then the stored credential)")
	_ = cmd.RegisterFlagCompletionFunc("format", cobra.FixedCompletions([]string{"yaml", "hcl", "sh"}, cobra.ShellCompDirectiveNoFileComp))
	return cmd
}

func init() {
	configCmd.AddCommand(newConfigPlanCommand())
	configCmd.AddCommand(newConfigApplyCommand())
	configCmd.AddCommand(newConfigExportCommand())
}
