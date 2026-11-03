package cmd

// `vulnetix gha publish campaigns`: mirror Vulnetix remediation campaigns as
// GitHub security campaigns.
//
// Vulnetix campaigns are read from the console (/api/site/v1/campaigns) with a
// vmt_ config token that carries the campaigns read scope. Each active
// campaign's open cohort items are matched to this organization's open code
// scanning alerts (rule.id == findingId, and the package for dependency
// items), which only exist once `gha publish code-scanning` has published
// them. The GitHub campaign is "[Vulnetix] <name>", its description ends with
// <!-- vulnetix-campaign:<uuid> --> so a later run finds and updates it, its
// ends_at is the Vulnetix deadline (or 90 days from creation) and its
// contact_link points back at the Vulnetix campaign. A completed or archived
// Vulnetix campaign closes its GitHub campaign.
//
// GitHub cannot change the alerts of a campaign once it exists. A second
// marker, <!-- vulnetix-scope:<hash> -->, records the frozen cohort the
// campaign was created from; with --recreate-on-scope-change a cohort that has
// since changed closes the old campaign and creates a new one.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v4/internal/campaigns"
	"github.com/vulnetix/cli/v4/internal/github"
)

var (
	campOrg         string
	campToken       string
	campRecreate    bool
	campDryRun      bool
	campDefaultDays int
)

var ghaPublishCampaignsCmd = &cobra.Command{
	Use:   "campaigns",
	Short: "Mirror Vulnetix remediation campaigns as GitHub security campaigns",
	Long: `Mirror Vulnetix remediation campaigns (Pro) as GitHub security campaigns
(POST /orgs/{org}/campaigns).

Each active Vulnetix campaign becomes "[Vulnetix] <name>". Its open items are
matched to the organization's open code scanning alerts: an alert belongs to an
item when its rule id is the item's finding id (and, for a package, the alert
names it). Publish code scanning first so the alerts exist. The campaign ends
at the Vulnetix deadline, or --default-days days from creation, and its contact
link is the Vulnetix campaign.

A description marker ties the GitHub campaign to the Vulnetix one, so a later
run updates it instead of adding another, and closes it once the Vulnetix
campaign is completed or archived. GitHub cannot change a campaign's alerts
after it is created; --recreate-on-scope-change closes the campaign and creates
a new one when the Vulnetix cohort has changed.

Two credentials are needed:

  Vulnetix  a config management token (vmt_...) with the campaigns read scope:
            --token, or VULNETIX_CONFIG_TOKEN. A token only ever reads here.
  GitHub    GITHUB_TOKEN, GH_TOKEN or 'gh auth token': an organization owner or
            security manager, as a PAT or GitHub App, on an organization with
            GitHub Advanced Security. The workflow GITHUB_TOKEN cannot manage
            campaigns.

Run it as an organization-level scheduled job, not on every push.`,
	Example: `  VULNETIX_CONFIG_TOKEN=vmt_... GH_TOKEN=$ORG_PAT vulnetix gha publish campaigns --org acme
  vulnetix gha publish campaigns --org acme --dry-run
  vulnetix gha publish campaigns --org acme --recreate-on-scope-change`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		org := campOrg
		if org == "" {
			org = os.Getenv("GITHUB_REPOSITORY_OWNER")
		}
		if org == "" {
			if r := os.Getenv("GITHUB_REPOSITORY"); r != "" {
				org, _, _ = strings.Cut(r, "/")
			}
		}
		if org == "" {
			return configUsage("pass --org (the GitHub organization that owns the repositories)")
		}
		a, err := resolveConfigAuth(campToken)
		if err != nil {
			return err
		}
		o := campaignsOptions{
			Org:         org,
			Recreate:    campRecreate,
			DryRun:      campDryRun,
			DefaultDays: campDefaultDays,
			Vulnetix:    campaigns.New(newSiteClient(a, "campaigns")),
			ConsoleURL:  webBaseURL(),
		}
		tok, _, err := github.ResolveToken()
		if err != nil {
			return err
		}
		o.GitHub = github.NewClient(tok)
		return runCampaignsPublish(cmd.Context(), o, os.Stderr)
	},
}

type campaignsOptions struct {
	Org         string
	Recreate    bool
	DryRun      bool
	DefaultDays int
	ConsoleURL  string
	Vulnetix    *campaigns.Client
	GitHub      *github.Client
	Now         func() time.Time
}

var scopeMarkerRe = regexp.MustCompile(`<!-- vulnetix-scope:([0-9a-f]+) -->`)

func scopeMarker(hash string) string { return "<!-- vulnetix-scope:" + hash + " -->" }

// scopeHash identifies a campaign's cohort by its item keys, which are stable
// for a frozen cohort and change only when the cohort does.
func scopeHash(items []campaigns.Item) string {
	keys := make([]string, 0, len(items))
	for _, it := range items {
		keys = append(keys, it.ItemKey)
	}
	sort.Strings(keys)
	sum := sha256.Sum256([]byte(strings.Join(keys, "\n")))
	return hex.EncodeToString(sum[:6])
}

// matchAlerts returns the numbers of the open alerts that belong to items. An
// alert is Vulnetix's when its category starts with "vulnetix/"; it matches a
// finding item by rule id (case-insensitively) and, when the item names a
// package, by the package appearing in the alert message; it matches a
// dependency item by an SCA category and the package in the message.
func matchAlerts(items []campaigns.Item, alerts []github.Alert) []int {
	var out []int
	for _, al := range alerts {
		cat := al.MostRecentInstance.Category
		if !strings.HasPrefix(cat, "vulnetix/") {
			continue
		}
		msg := strings.ToLower(al.MostRecentInstance.Message.Text)
		for _, it := range items {
			if alertMatches(it, al, cat, msg) {
				out = append(out, al.Number)
				break
			}
		}
	}
	sort.Ints(out)
	return out
}

func alertMatches(it campaigns.Item, al github.Alert, cat, msg string) bool {
	pkg := strings.ToLower(it.PackageName)
	switch it.Kind {
	case "dependency":
		return pkg != "" && strings.HasPrefix(cat, "vulnetix/sca/") && strings.Contains(msg, pkg)
	default:
		if it.FindingID == "" || !strings.EqualFold(al.Rule.ID, it.FindingID) {
			return false
		}
		return pkg == "" || strings.Contains(msg, pkg)
	}
}

// repoFullName qualifies a Vulnetix repository name with the organization.
func repoFullName(org, name string) (string, bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", false
	}
	if !strings.Contains(name, "/") {
		return org + "/" + name, true
	}
	owner, _, _ := strings.Cut(name, "/")
	return name, strings.EqualFold(owner, org)
}

// alertCache holds each repository's id and open alerts for one run.
type alertCache struct {
	gh     *github.Client
	ids    map[string]int
	alerts map[string][]github.Alert
	failed map[string]error
}

func (c *alertCache) get(ctx context.Context, repo string) (int, []github.Alert, error) {
	if err, bad := c.failed[repo]; bad {
		return 0, nil, err
	}
	if id, ok := c.ids[repo]; ok {
		return id, c.alerts[repo], nil
	}
	id, err := c.gh.RepositoryID(ctx, repo)
	if err == nil {
		var al []github.Alert
		al, err = c.gh.ListOpenAlerts(ctx, repo)
		if err == nil {
			c.ids[repo], c.alerts[repo] = id, al
			return id, al, nil
		}
	}
	c.failed[repo] = err
	return 0, nil, err
}

// mapCampaignAlerts resolves a campaign's open items to alerts per repository.
// skipped counts items in repositories outside the organization or whose
// alerts could not be read.
func mapCampaignAlerts(ctx context.Context, cache *alertCache, org string, open []campaigns.Item, w io.Writer) (groups []github.CampaignAlerts, total, skipped int) {
	byRepo := map[string][]campaigns.Item{}
	for _, it := range open {
		repo, ok := repoFullName(org, it.RepoName)
		if !ok {
			skipped++
			continue
		}
		byRepo[repo] = append(byRepo[repo], it)
	}
	repos := make([]string, 0, len(byRepo))
	for r := range byRepo {
		repos = append(repos, r)
	}
	sort.Strings(repos)
	for _, repo := range repos {
		id, alerts, err := cache.get(ctx, repo)
		if err != nil {
			skipped += len(byRepo[repo])
			fmt.Fprintf(w, "  campaigns: %s: alerts not read: %v%s\n", repo, err, permissionHint(err, "security events read on the repository (code scanning enabled)"))
			continue
		}
		nums := matchAlerts(byRepo[repo], alerts)
		if len(nums) == 0 {
			continue
		}
		groups = append(groups, github.CampaignAlerts{RepositoryID: id, AlertNumbers: nums})
		total += len(nums)
	}
	return groups, total, skipped
}

// capAlerts keeps at most limit alerts, in order.
func capAlerts(groups []github.CampaignAlerts, limit int) ([]github.CampaignAlerts, int) {
	var out []github.CampaignAlerts
	kept := 0
	for _, g := range groups {
		if kept >= limit {
			break
		}
		if room := limit - kept; len(g.AlertNumbers) > room {
			g.AlertNumbers = g.AlertNumbers[:room]
		}
		kept += len(g.AlertNumbers)
		out = append(out, g)
	}
	return out, kept
}

// current picks the GitHub campaign for a Vulnetix one: the highest-numbered
// open one, else the highest-numbered closed one. The rest of the open ones are
// returned as duplicates to close.
func current(all []github.Campaign) (cur *github.Campaign, dupes []github.Campaign) {
	sort.Slice(all, func(i, j int) bool { return all[i].Number > all[j].Number })
	for i := range all {
		if all[i].State == github.CampaignOpen {
			if cur == nil || cur.State != github.CampaignOpen {
				cur = &all[i]
			} else {
				dupes = append(dupes, all[i])
			}
		}
	}
	if cur == nil && len(all) > 0 {
		cur = &all[0]
	}
	return cur, dupes
}

// campaignDescription is the text, the campaign marker and the scope marker,
// within GitHub's limit (the markers are kept whole).
func campaignDescription(c campaigns.Campaign, hash string) string {
	scope := scopeMarker(hash)
	marker := github.CampaignMarker(c.UUID)
	room := github.CampaignDescriptionMax - len(marker) - len(scope) - 2
	text := strings.TrimSpace(c.Description)
	if text == "" {
		text = "Remediation campaign managed in Vulnetix."
	}
	if len(text) > room {
		text = truncateUTF8(text, room-3) + "..."
	}
	return text + "\n" + marker + "\n" + scope
}

func runCampaignsPublish(ctx context.Context, o campaignsOptions, w io.Writer) error {
	if ctx == nil {
		ctx = context.Background()
	}
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	if o.DefaultDays <= 0 {
		o.DefaultDays = 90
	}
	vx, err := o.Vulnetix.List(ctx, true)
	if err != nil {
		if errors.Is(err, campaigns.ErrNotEntitled) {
			fmt.Fprintf(w, "  campaigns: %v; nothing to publish\n", err)
			return nil
		}
		var he *configHTTPError
		if errors.As(err, &he) && (he.Status == 401 || he.Status == 403) {
			return fmt.Errorf("%w (use a vmt_ config token with the campaigns read scope: --token or %s)", err, configTokenEnv)
		}
		return err
	}
	existing, err := o.GitHub.ListCampaigns(ctx, o.Org)
	if err != nil {
		return fmt.Errorf("campaigns: %w%s", err, permissionHint(err, "organization owner or security manager rights (a PAT or GitHub App) and GitHub Advanced Security"))
	}
	byUUID := map[string][]github.Campaign{}
	for _, g := range existing {
		if id := github.CampaignMarkerOf(g.Description); id != "" {
			byUUID[id] = append(byUUID[id], g)
		}
	}
	cache := &alertCache{gh: o.GitHub, ids: map[string]int{}, alerts: map[string][]github.Alert{}, failed: map[string]error{}}
	var failed []string
	patch := func(g github.Campaign, p github.CampaignPatch, what string) error {
		if o.DryRun {
			fmt.Fprintf(w, "  campaigns: would %s #%d (%s)\n", what, g.Number, g.Name)
			return nil
		}
		if _, err := o.GitHub.PatchCampaign(ctx, o.Org, g.Number, p); err != nil {
			return err
		}
		fmt.Fprintf(w, "  campaigns: %s #%d (%s)\n", what, g.Number, g.Name)
		return nil
	}
	for _, c := range vx {
		cur, dupes := current(byUUID[c.UUID])
		if c.Closed() {
			if cur != nil && cur.State == github.CampaignOpen {
				if err := patch(*cur, github.CampaignPatch{State: github.CampaignClosed}, "closed (Vulnetix campaign "+strings.ToLower(c.Status)+")"); err != nil {
					failed = append(failed, c.Name)
					fmt.Fprintf(w, "  campaigns: close %q: %v\n", c.Name, err)
				}
			}
			for _, d := range dupes {
				_ = patch(d, github.CampaignPatch{State: github.CampaignClosed}, "closed duplicate")
			}
			continue
		}

		all, err := o.Vulnetix.Items(ctx, c.UUID, "")
		if err != nil {
			failed = append(failed, c.Name)
			fmt.Fprintf(w, "  campaigns: %q: %v\n", c.Name, err)
			continue
		}
		hash := scopeHash(all)
		var open []campaigns.Item
		for _, it := range all {
			if it.State == "open" {
				open = append(open, it)
			}
		}
		end := now().UTC().Add(time.Duration(o.DefaultDays) * 24 * time.Hour)
		if d, ok := c.Deadline(); ok {
			end = d
		}
		contact := strings.TrimRight(o.ConsoleURL, "/") + "/resolve/campaigns/" + c.UUID

		create := func(why string) {
			groups, total, skipped := mapCampaignAlerts(ctx, cache, o.Org, open, w)
			if total == 0 {
				fmt.Fprintf(w, "  campaigns: %q: no open code scanning alert matches its %d open item(s); publish code scanning first (not created)\n", c.Name, len(open))
				return
			}
			groups, kept := capAlerts(groups, github.CampaignAlertsMax)
			if kept < total {
				fmt.Fprintf(w, "  campaigns: %q: %d alerts, GitHub takes %d; the worst-listed %d are included\n", c.Name, total, github.CampaignAlertsMax, kept)
			}
			if skipped > 0 {
				fmt.Fprintf(w, "  campaigns: %q: %d item(s) skipped (repository outside %s or alerts unreadable)\n", c.Name, skipped, o.Org)
			}
			req := github.CampaignCreate{
				Name: github.CampaignName(c.Name), Description: campaignDescription(c, hash),
				EndsAt: github.CampaignEnd(end), ContactLink: contact, CodeScanningAlerts: groups,
			}
			if o.DryRun {
				fmt.Fprintf(w, "  campaigns: would create %q with %d alert(s) in %d repositor(ies), ends %s%s\n", req.Name, kept, len(groups), req.EndsAt, why)
				return
			}
			g, err := o.GitHub.CreateCampaign(ctx, o.Org, req)
			if err != nil {
				failed = append(failed, c.Name)
				fmt.Fprintf(w, "  campaigns: create %q: %v%s\n", req.Name, err, permissionHint(err, "organization owner or security manager rights (a PAT or GitHub App) and GitHub Advanced Security"))
				return
			}
			fmt.Fprintf(w, "  campaigns: created #%d %q with %d alert(s)%s\n", g.Number, g.Name, kept, why)
		}

		switch {
		case cur == nil:
			create("")
		case cur.State != github.CampaignOpen:
			fmt.Fprintf(w, "  campaigns: #%d (%s) was closed in GitHub; left closed\n", cur.Number, cur.Name)
		default:
			prev := ""
			if m := scopeMarkerRe.FindStringSubmatch(cur.Description); len(m) == 2 {
				prev = m[1]
			}
			if prev != "" && prev != hash {
				if !o.Recreate {
					fmt.Fprintf(w, "  campaigns: #%d (%s): the Vulnetix cohort changed and GitHub cannot change a campaign's alerts; pass --recreate-on-scope-change to replace it\n", cur.Number, cur.Name)
				} else {
					// Create the replacement first, so a failure leaves the old
					// campaign running rather than none.
					before := len(failed)
					create("; replaces #" + fmt.Sprint(cur.Number))
					if len(failed) == before && !o.DryRun {
						if err := patch(*cur, github.CampaignPatch{State: github.CampaignClosed}, "closed (replaced)"); err != nil {
							failed = append(failed, c.Name)
							fmt.Fprintf(w, "  campaigns: close #%d: %v\n", cur.Number, err)
						}
					}
					for _, d := range dupes {
						_ = patch(d, github.CampaignPatch{State: github.CampaignClosed}, "closed duplicate")
					}
					continue
				}
			}
			p := github.CampaignPatch{}
			if n := github.CampaignName(c.Name); n != cur.Name {
				p.Name = n
			}
			if d := campaignDescription(c, scopeOrHash(prev, hash)); d != cur.Description {
				p.Description = d
			}
			if _, ok := c.Deadline(); ok && !sameInstant(cur.EndsAt, end) {
				p.EndsAt = github.CampaignEnd(end)
			}
			if cur.ContactLink != contact {
				p.ContactLink = contact
			}
			if (p == github.CampaignPatch{}) {
				fmt.Fprintf(w, "  campaigns: #%d (%s) is up to date\n", cur.Number, cur.Name)
			} else if err := patch(*cur, p, "updated"); err != nil {
				failed = append(failed, c.Name)
				fmt.Fprintf(w, "  campaigns: update #%d: %v\n", cur.Number, err)
			}
			for _, d := range dupes {
				_ = patch(d, github.CampaignPatch{State: github.CampaignClosed}, "closed duplicate")
			}
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("campaigns failed for %s", strings.Join(failed, ", "))
	}
	return nil
}

// scopeOrHash keeps the scope the campaign was created with, so an update that
// only edits text does not make the next run think the cohort changed.
func scopeOrHash(prev, hash string) string {
	if prev != "" {
		return prev
	}
	return hash
}

func sameInstant(s string, t time.Time) bool {
	p, err := time.Parse(time.RFC3339, s)
	return err == nil && p.Truncate(time.Second).Equal(t.Truncate(time.Second))
}

func init() {
	f := ghaPublishCampaignsCmd.Flags()
	f.StringVar(&campOrg, "org", "", "GitHub organization (default: GITHUB_REPOSITORY_OWNER)")
	f.StringVar(&campToken, "token", "", "Vulnetix config management token (vmt_...) with the campaigns read scope (default: VULNETIX_CONFIG_TOKEN)")
	f.BoolVar(&campRecreate, "recreate-on-scope-change", false, "Close and recreate a GitHub campaign whose Vulnetix cohort changed (GitHub cannot change a campaign's alerts)")
	f.BoolVar(&campDryRun, "dry-run", false, "Read from Vulnetix and GitHub and print what would change; write nothing")
	f.IntVar(&campDefaultDays, "default-days", 90, "Days until a campaign with no Vulnetix deadline ends")
	ghaPublishCmd.AddCommand(ghaPublishCampaignsCmd)
}

// truncateUTF8 cuts s to at most n bytes without splitting a character.
func truncateUTF8(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return strings.TrimSpace(s[:n])
}
