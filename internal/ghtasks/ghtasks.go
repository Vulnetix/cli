// Package ghtasks runs the Vulnetix GitHub posture engine (vdb-sca-match
// ghaudit) for the `vulnetix gha` analysis tasks: workflows, actions,
// settings, org and audit. It owns everything the engine leaves to its
// callers: reading local workflow files, talking to the GitHub REST API,
// and rendering a report.
package ghtasks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Vulnetix/vdb-sca-match/ghaudit"
)

// DefaultAPIURL is api.github.com; GitHub Enterprise Server is passed in.
const DefaultAPIURL = "https://api.github.com"

// RESTGetter is a ghaudit.Getter over net/http with a token.
type RESTGetter struct {
	BaseURL string
	Token   string
	Client  *http.Client
	// Calls counts requests, for the report.
	Calls int
}

// NewRESTGetter returns a getter for baseURL ("" for github.com).
func NewRESTGetter(baseURL, token string) *RESTGetter {
	if baseURL == "" {
		baseURL = DefaultAPIURL
	}
	return &RESTGetter{BaseURL: strings.TrimRight(baseURL, "/"), Token: token, Client: &http.Client{Timeout: 30 * time.Second}}
}

// ErrRateLimited is returned when GitHub refuses for quota.
var ErrRateLimited = errors.New("GitHub API rate limit exhausted")

// Get implements ghaudit.Getter.
func (g *RESTGetter) Get(ctx context.Context, path string, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.BaseURL+path, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if g.Token != "" {
		req.Header.Set("Authorization", "Bearer "+g.Token)
	}
	g.Calls++
	resp, err := g.Client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		if (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests) && resp.Header.Get("X-RateLimit-Remaining") == "0" {
			return resp.StatusCode, ErrRateLimited
		}
		return resp.StatusCode, fmt.Errorf("GET %s: HTTP %d", path, resp.StatusCode)
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(out); err != nil {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

// LoadLocal reads the files the engine evaluates from a checkout: workflows,
// action metadata under .github/ and at the root, and CODEOWNERS.
func LoadLocal(root string) (map[string][]byte, error) {
	files := map[string][]byte{}
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		// A single file: evaluate it as a workflow unless it is an action.
		b, err := os.ReadFile(root)
		if err != nil {
			return nil, err
		}
		name := filepath.Base(root)
		if ghaudit.IsActionPath(name) {
			files[name] = b
		} else {
			files[".github/workflows/"+name] = b
		}
		return files, nil
	}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", ".venv":
				return filepath.SkipDir
			}
			// Only .github and the root matter; do not walk a whole monorepo.
			if rel != "." && !strings.HasPrefix(rel, ".github") && rel != "docs" {
				return filepath.SkipDir
			}
			return nil
		}
		if ghaudit.IsWorkflowPath(rel) || ghaudit.IsActionPath(rel) || ghaudit.IsRelevantPath(rel) {
			if fi, err := d.Info(); err == nil && fi.Size() > 1<<20 {
				return nil
			}
			b, err := os.ReadFile(p)
			if err == nil {
				files[rel] = b
			}
		}
		return nil
	})
	return files, err
}

var scpLike = regexp.MustCompile(`^([^@]+@)?([^:]+):(.+)$`)

// RepoFromRemote returns owner/name for a github.com (or apiHost) remote URL.
func RepoFromRemote(remote, host string) string {
	remote = strings.TrimSuffix(strings.TrimSpace(remote), ".git")
	if host == "" {
		host = "github.com"
	}
	var h, p string
	if strings.Contains(remote, "://") {
		u, err := url.Parse(remote)
		if err != nil {
			return ""
		}
		h, p = u.Hostname(), u.Path
	} else if m := scpLike.FindStringSubmatch(remote); m != nil {
		h, p = m[2], m[3]
	}
	if !strings.EqualFold(h, host) {
		return ""
	}
	parts := strings.Split(strings.Trim(p, "/"), "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	return parts[0] + "/" + parts[1]
}

// HostForAPI is the web host that pairs with an API base URL.
func HostForAPI(apiURL string) string {
	if apiURL == "" || apiURL == DefaultAPIURL {
		return "github.com"
	}
	u, err := url.Parse(apiURL)
	if err != nil {
		return "github.com"
	}
	return u.Hostname()
}

// Summary counts a report for display and exit codes.
type Summary struct {
	BySeverity map[ghaudit.Severity]int `json:"bySeverity"`
	Total      int                      `json:"total"`
	Unknown    []string                 `json:"notEvaluated,omitempty"` // rule ids not evaluated for missing facts
	Files      int                      `json:"files"`
}

// Summarise counts findings and the rules that could not run.
func Summarise(rep *ghaudit.Report, files int) Summary {
	s := Summary{BySeverity: map[ghaudit.Severity]int{}, Total: len(rep.Findings), Files: files}
	for _, f := range rep.Findings {
		s.BySeverity[f.Severity]++
	}
	seen := map[string]bool{}
	for _, c := range rep.Coverage {
		if c.State == "unknown" && !seen[c.RuleID] {
			seen[c.RuleID] = true
			s.Unknown = append(s.Unknown, c.RuleID)
		}
	}
	sort.Strings(s.Unknown)
	return s
}

// FailsAt reports whether any finding is at or above sev.
func FailsAt(rep *ghaudit.Report, sev ghaudit.Severity) bool {
	if sev == "" {
		return false
	}
	for _, f := range rep.Findings {
		if f.Severity.AtLeast(sev) {
			return true
		}
	}
	return false
}

// WriteTable renders a report for a terminal.
func WriteTable(w io.Writer, rep *ghaudit.Report, s Summary, notes []string) {
	if len(rep.Findings) == 0 {
		fmt.Fprintln(w, "No GitHub misconfigurations found.")
	}
	for _, f := range rep.Findings {
		where := f.Location.Path
		if where != "" && f.Location.StartLine > 0 {
			where = fmt.Sprintf("%s:%d", where, f.Location.StartLine)
		}
		if where == "" {
			where = strings.TrimSpace(f.Location.Scope + " settings " + f.Location.SettingsPath)
		}
		fmt.Fprintf(w, "%-13s %-11s %s\n", strings.ToUpper(string(f.Severity)), f.RuleID, f.Title)
		fmt.Fprintf(w, "              %s\n", where)
		fmt.Fprintf(w, "              %s\n", f.Message)
		for _, a := range f.Adjustments {
			fmt.Fprintf(w, "              · %s\n", a)
		}
		if f.Fix != nil {
			fmt.Fprintf(w, "              fix: %s\n", f.Fix.Description)
		}
		fmt.Fprintln(w)
	}
	var parts []string
	for _, sev := range []ghaudit.Severity{ghaudit.Critical, ghaudit.High, ghaudit.Medium, ghaudit.Low, ghaudit.Info} {
		if n := s.BySeverity[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	fmt.Fprintf(w, "%d finding(s) in %d file(s)", s.Total, s.Files)
	if len(parts) > 0 {
		fmt.Fprintf(w, ": %s", strings.Join(parts, ", "))
	}
	fmt.Fprintln(w)
	if len(s.Unknown) > 0 {
		fmt.Fprintf(w, "%d rule(s) not evaluated for want of GitHub settings (they are not passes): %s\n", len(s.Unknown), strings.Join(s.Unknown, ", "))
	}
	for _, n := range notes {
		fmt.Fprintf(w, "note: %s\n", n)
	}
	for _, e := range rep.Errors {
		fmt.Fprintf(w, "error: %s\n", e)
	}
}
