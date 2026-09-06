package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/vulnetix/cli/v3/internal/display"
)

const (
	skillsUpstreamRepo = "Vulnetix/pix-ai-coding-assistant"

	// The interoperable store that `npx skills` installs into, and the lock it
	// keeps beside it. Every host directory this CLI knows about is populated
	// by symlinks into the store, so the store plus the lock is the whole
	// record of what a machine has.
	skillsStoreRel = ".agents/skills"
	skillsLockRel  = ".agents/.skill-lock.json"
)

// currentVulnetixSkills is the skill set of the latest release of
// skillsUpstreamRepo. It is the offline fallback for resolveUpstreamSkills and
// the one list every skills subcommand reads.
//
// Three hand-copied lists used to live in this package, disagreeing with each
// other and with upstream, and all of them still named skills the release had
// removed: `skills install` re-added what a release had deliberately dropped,
// and nothing could ever notice a skill that had been removed upstream.
var currentVulnetixSkills = []string{
	"container-scan", "dashboard", "dep-resolve", "dependency-choice",
	"detection-rules", "eol-check", "exploit-test", "fix", "iac-scan",
	"license-check", "repo-impact", "sast-scan", "sbom-generate",
	"secret-scan", "secure-code-write", "typosquat-check", "verify-fix",
	"vex-publish",
}

func skillSet(names []string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, n := range names {
		if n = strings.TrimSpace(n); n != "" {
			out[n] = true
		}
	}
	return out
}

// upstreamSkills is the set a machine should converge on, and where it came from.
type upstreamSkills struct {
	Names map[string]bool
	Tag   string // release tag, or "embedded" when the network was unavailable
}

// resolveUpstreamSkills asks GitHub for the skills directory of the latest
// release and falls back to the embedded list. The release tag, not main:
// `gh skill install` pins to the latest release, so the release is what a
// user has.
func resolveUpstreamSkills() upstreamSkills {
	tag, names, err := fetchUpstreamSkills(4 * time.Second)
	if err != nil || len(names) == 0 {
		return upstreamSkills{Names: skillSet(currentVulnetixSkills), Tag: "embedded"}
	}
	return upstreamSkills{Names: skillSet(names), Tag: tag}
}

func fetchUpstreamSkills(timeout time.Duration) (string, []string, error) {
	client := &http.Client{Timeout: timeout}

	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := githubJSON(client, "https://api.github.com/repos/"+skillsUpstreamRepo+"/releases/latest", &rel); err != nil {
		return "", nil, err
	}
	if rel.TagName == "" {
		return "", nil, errors.New("latest release has no tag")
	}

	var entries []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if err := githubJSON(client, "https://api.github.com/repos/"+skillsUpstreamRepo+"/contents/skills?ref="+rel.TagName, &entries); err != nil {
		return "", nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.Type == "dir" && !strings.HasPrefix(e.Name, "_") {
			names = append(names, e.Name)
		}
	}
	sort.Strings(names)
	return rel.TagName, names, nil
}

func githubJSON(client *http.Client, url string, out any) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "vulnetix-cli")
	if tok := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

// skillLock is ~/.agents/.skill-lock.json, edited in place. Only the entries
// touched are changed; every other field, and every entry from another
// source, is written back exactly as read.
type skillLock struct {
	path   string
	doc    map[string]any
	skills map[string]map[string]any
}

func loadSkillLock(path string) (*skillLock, error) {
	l := &skillLock{path: path, doc: map[string]any{}, skills: map[string]map[string]any{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		l.doc = map[string]any{"version": 3, "skills": map[string]any{}}
		return l, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &l.doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	raw, _ := l.doc["skills"].(map[string]any)
	for name, v := range raw {
		if m, ok := v.(map[string]any); ok {
			l.skills[name] = m
		}
	}
	return l, nil
}

func (l *skillLock) sourceOf(name string) string {
	if m, ok := l.skills[name]; ok {
		if s, ok := m["source"].(string); ok {
			return s
		}
	}
	return ""
}

func (l *skillLock) remove(name string) {
	delete(l.skills, name)
	if raw, ok := l.doc["skills"].(map[string]any); ok {
		delete(raw, name)
	}
}

func (l *skillLock) save() error {
	if err := os.MkdirAll(filepath.Dir(l.path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(l.doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(l.path, append(b, '\n'), 0o644)
}

func isVulnetixSource(src string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(src)), "vulnetix/")
}

// pruneTarget is one skill the plan will remove.
type pruneTarget struct {
	Name   string
	Source string
	Reason string
	Store  string   // the directory under the store; empty when only the lock knows it
	Links  []string // host symlinks that resolve into Store
}

type prunePlan struct {
	Store   string
	Lock    string
	Targets []pruneTarget
	Missing []string // upstream skills with no local copy at all
}

// planPrune decides what to remove without touching anything.
//
// A skill is a candidate only when the lock attributes it to a Vulnetix
// source. Real directories in a host skills folder are never candidates, and a
// symlink is only followed when it resolves into the store entry for that
// skill: a user's own skill, or a symlink they pointed elsewhere, is not ours
// to delete.
func planPrune(home string, hostDirs []string, current map[string]bool, only []string) (*prunePlan, *skillLock, error) {
	store := filepath.Join(home, filepath.FromSlash(skillsStoreRel))
	lockPath := filepath.Join(home, filepath.FromSlash(skillsLockRel))
	lock, err := loadSkillLock(lockPath)
	if err != nil {
		return nil, nil, err
	}

	onlySet := skillSet(only)
	names := make([]string, 0, len(lock.skills))
	for name := range lock.skills {
		names = append(names, name)
	}
	sort.Strings(names)

	plan := &prunePlan{Store: store, Lock: lockPath}
	for _, name := range names {
		src := lock.sourceOf(name)
		if !isVulnetixSource(src) {
			continue
		}
		if len(only) > 0 {
			if !onlySet[name] {
				continue
			}
		} else if current[name] {
			continue
		}
		t := pruneTarget{Name: name, Source: src, Reason: "removed upstream"}
		if len(only) > 0 {
			t.Reason = "requested"
		}
		storeDir := filepath.Join(store, name)
		if fi, err := os.Lstat(storeDir); err == nil && fi.IsDir() {
			t.Store = storeDir
		} else if len(only) == 0 {
			t.Reason = "lock entry without files"
		}
		t.Links = linksInto(hostDirs, store, name)
		plan.Targets = append(plan.Targets, t)
	}

	if len(only) == 0 {
		for name := range current {
			if _, inLock := lock.skills[name]; inLock {
				continue
			}
			if fi, err := os.Lstat(filepath.Join(store, name)); err == nil && fi.IsDir() {
				continue
			}
			plan.Missing = append(plan.Missing, name)
		}
		sort.Strings(plan.Missing)
	}

	return plan, lock, nil
}

// linksInto returns every <dir>/<name> across hostDirs that is a symlink
// resolving to <store>/<name>. The store itself is skipped: its entries are
// the real directories, handled separately.
func linksInto(hostDirs []string, store, name string) []string {
	want := filepath.Clean(filepath.Join(store, name))
	var out []string
	for _, dir := range hostDirs {
		if filepath.Clean(dir) == filepath.Clean(store) {
			continue
		}
		p := filepath.Join(dir, name)
		fi, err := os.Lstat(p)
		if err != nil || fi.Mode()&os.ModeSymlink == 0 {
			continue
		}
		target, err := os.Readlink(p)
		if err != nil {
			continue
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(dir, target)
		}
		if filepath.Clean(target) == want {
			out = append(out, p)
		}
	}
	return out
}

// applyPrune removes the planned targets: host symlinks first, then the store
// directory, then the lock entry, and writes the lock once at the end.
func applyPrune(plan *prunePlan, lock *skillLock) error {
	for _, t := range plan.Targets {
		for _, l := range t.Links {
			if err := os.Remove(l); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove %s: %w", l, err)
			}
		}
		if t.Store != "" {
			if err := os.RemoveAll(t.Store); err != nil {
				return fmt.Errorf("remove %s: %w", t.Store, err)
			}
		}
		lock.remove(t.Name)
	}
	return lock.save()
}

// pruneHostDirs is every known host skills directory that exists on this
// machine, resolved against home. Relative entries are project-scoped and
// never pruned from here.
func pruneHostDirs(home string) []string {
	seen := map[string]bool{}
	var out []string
	for _, dirs := range agentDirs {
		for _, d := range dirs {
			if !strings.HasPrefix(d, "~") && !filepath.IsAbs(d) {
				continue
			}
			p := expandHomeIn(home, d)
			if seen[p] {
				continue
			}
			seen[p] = true
			if fi, err := os.Stat(p); err == nil && fi.IsDir() {
				out = append(out, p)
			}
		}
	}
	sort.Strings(out)
	return out
}

func expandHomeIn(home, p string) string {
	if strings.HasPrefix(p, "~") {
		return filepath.Join(home, filepath.FromSlash(strings.TrimPrefix(strings.TrimPrefix(p, "~"), "/")))
	}
	return filepath.FromSlash(os.ExpandEnv(p))
}

var skillsPruneYes bool

var skillsPruneCmd = &cobra.Command{
	Use:   "prune [skill...]",
	Short: "Remove Vulnetix skills the current release no longer ships",
	Long: `Remove Vulnetix skills that are installed on this machine but absent from
the latest release of ` + skillsUpstreamRepo + `.

Neither 'npx skills update' nor 'gh skills update' deletes a skill that a
release removed, so a machine that has followed several releases accumulates
skills upstream retired on purpose. This compares ~/.agents/.skill-lock.json
against the release's skills directory and removes the leftovers: every host
symlink that points into the skill's store directory, the store directory
itself, and the lock entry. Only entries the lock attributes to a Vulnetix
source are ever touched, and never a real directory in a host's skills folder.

Without --yes this only prints what it would remove. Name skills explicitly to
prune those regardless of whether upstream still ships them.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dc := display.FromCommand(cmd)
		t := dc.Term
		out := cmd.OutOrStdout()

		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		up := resolveUpstreamSkills()
		plan, lock, err := planPrune(home, pruneHostDirs(home), up.Names, args)
		if err != nil {
			return err
		}

		fmt.Fprintln(out, display.Subheader(t, "Pruning Vulnetix Skills"))
		fmt.Fprintf(out, "  %s Release: %s (%d skills)\n", display.Muted(t, "•"), display.Bold(t, up.Tag), len(up.Names))

		if len(plan.Targets) == 0 {
			fmt.Fprintf(out, "  %s %s\n", display.CheckMark(t), display.Success(t, "Nothing to prune."))
			printMissingSkills(out, t, plan.Missing)
			return nil
		}

		for _, tg := range plan.Targets {
			where := "lock entry only"
			if tg.Store != "" {
				where = fmt.Sprintf("%s + %d link(s)", tg.Store, len(tg.Links))
			}
			fmt.Fprintf(out, "  %s %s  %s  %s\n", display.WarningMark(t), display.Bold(t, tg.Name), display.Muted(t, tg.Reason), display.Muted(t, where))
		}

		if !skillsPruneYes {
			fmt.Fprintf(out, "\n  %s\n", display.Muted(t, fmt.Sprintf("Dry run: %d skill(s) would be removed. Re-run with --yes to apply.", len(plan.Targets))))
			printMissingSkills(out, t, plan.Missing)
			return nil
		}

		if err := applyPrune(plan, lock); err != nil {
			return err
		}
		fmt.Fprintf(out, "\n  %s %s\n", display.CheckMark(t), display.Success(t, fmt.Sprintf("Removed %d skill(s); lock updated at %s", len(plan.Targets), plan.Lock)))
		printMissingSkills(out, t, plan.Missing)
		return nil
	},
}

func printMissingSkills(out io.Writer, t *display.Terminal, missing []string) {
	if len(missing) == 0 {
		return
	}
	fmt.Fprintf(out, "  %s %s %s\n", display.Muted(t, "ℹ"),
		display.Muted(t, "Shipped upstream but not installed here:"),
		strings.Join(missing, ", "))
	fmt.Fprintf(out, "    %s\n", display.Muted(t, "Run `vulnetix skills install` to add them."))
}
