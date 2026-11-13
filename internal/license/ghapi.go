package license

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/vulnetix/cli/v4/internal/ghquota"
)

// The licence lookups asked GitHub through `gh api`, one process per request:
// 645 processes on every scan of this repository (about 70 CPU seconds), most
// of them for repositories whose licence GitHub cannot name and which are
// therefore asked again each run. ghAPIDirect answers the same requests in
// process, with the token gh itself uses (`gh auth token`, asked once), and
// renders each answer exactly as `gh api ... --jq <expr>` prints it, for the
// three expressions this package uses. Anything else, a non-default GitHub
// host, or a path that would need escaping, still goes through gh.
// TestGHAPIDirectMatchesGH compares the two against the live API when
// VULNETIX_GH_PARITY is set.

var (
	ghTokenOnce sync.Once
	ghToken     string
)

// lookupToken is the token the in-process lookups send: gh's (which is
// GITHUB_TOKEN or GH_TOKEN when either is set, since gh reads them first), else,
// with no gh, GITHUB_TOKEN or GH_TOKEN themselves.
func lookupToken() string {
	if t := ghAuthToken(); t != "" {
		return t
	}
	if isGHCLIAvailable() {
		return "" // gh answers for itself (a non-default GH_HOST)
	}
	return findGitHubPAT()
}

// ghAuthToken is the token gh sends to github.com, or "" when gh has none.
func ghAuthToken() string {
	ghTokenOnce.Do(func() {
		if os.Getenv("GH_HOST") != "" && os.Getenv("GH_HOST") != "github.com" {
			return
		}
		out, err := exec.Command("gh", "auth", "token").Output()
		if err == nil {
			ghToken = strings.TrimSpace(string(out))
		}
	})
	return ghToken
}

var ghHTTP = &http.Client{Timeout: 60 * time.Second}

// ghAPIBase is the REST root gh uses for github.com; a var for tests.
var ghAPIBase = "https://api.github.com/"

// ghHTTPError is an HTTP error status; its text carries "HTTP <status>" as
// gh's message does, which is what tells a definitive miss from a failure.
type ghHTTPError struct{ status int }

func (e ghHTTPError) Error() string { return fmt.Sprintf("gh api: HTTP %d", e.status) }

// plainAPIPath is a path gh and net/http send byte for byte alike; anything
// else (globs, spaces, escapes) is left to gh.
var plainAPIPath = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)

// licenseDirFilter is the select in the directory-listing expression.
var licenseDirFilter = regexp.MustCompile(`(?i)(^licen|^copying)`)

const (
	jqSPDX    = ".license.spdx_id"
	jqContent = ".content"
	jqLicDir  = `[.[] | select(.name | test("(?i)(^licen|^copying)")) | .name] | .[]`
)

// ghAPIDirect is `gh api <path> --jq <expr>` answered in process. ok is false
// when it cannot answer the way gh would, and the caller runs gh.
func ghAPIDirect(path, expr string) (out []byte, ok bool, err error) {
	switch expr {
	case jqSPDX, jqContent, jqLicDir:
	default:
		return nil, false, nil
	}
	if !plainAPIPath.MatchString(path) {
		return nil, false, nil
	}
	if lookupToken() == "" {
		return nil, false, nil
	}
	resp, derr := githubGet(ghAPIBase + path)
	if derr != nil {
		return nil, true, derr
	}
	defer resp.Body.Close()
	body, berr := io.ReadAll(resp.Body)
	if berr != nil {
		return nil, true, berr
	}
	if resp.StatusCode >= 400 {
		return nil, true, ghHTTPError{resp.StatusCode}
	}
	out, err = renderGHJQ(body, expr)
	return out, true, err
}

// ── The request budget ───────────────────────────────────────────────────
//
// Every GitHub request this package makes goes through githubGet or ghAPICall,
// and both spend from one budget per process (internal/ghquota, the one
// analyze's forge pass uses). Inside GitHub Actions the job token's quota
// belongs to the whole repository: on the push that merged Vulnetix/cli#341,
// the scan jobs' licence lookups took it from 4,913 requests to none in under
// three and a half minutes, so the analyze job's forge pass, and SCA's own
// SARIF upload, found it spent. Licences are the least important use of that
// quota (the Vulnetix store, the registries and deps.dev answer most of
// them), so in Actions the lookups keep ciLicenseShare of the limit for
// everything else. The remaining count is the repository's, the same number
// in every job, so the floor holds for the run however many jobs look up
// licences at once.

// ciLicenseShare is the fraction of the limit the lookups keep inside GitHub
// Actions: with a 5,000 limit they stop at 4,000 left, above the 2,500 the
// forge pass keeps for CodeQL and the release.
const ciLicenseShare = 0.8

const licenseBudgetHint = "Their licences stay UNKNOWN in this run; a later run, or one with a token of its own, resolves them."

// errGitHubBudget is a request the budget did not make.
var errGitHubBudget = errors.New("GitHub licence lookups stopped at this run's share of the API rate limit")

var (
	ghBudgetMu   sync.Mutex
	ghBudget     *ghquota.Budget
	ghSeedOnce   sync.Once
	ghNoticeOnce sync.Once
	// noticeOut is where the lookups say they stopped; a var for tests.
	noticeOut io.Writer = os.Stderr
)

// githubBudget is this process's licence-lookup budget.
func githubBudget() *ghquota.Budget {
	ghBudgetMu.Lock()
	defer ghBudgetMu.Unlock()
	if ghBudget == nil {
		share := ghquota.DefaultShare
		if inGitHubActions() {
			share = ciLicenseShare
		}
		ghBudget = ghquota.NewBudget(ghquota.Keep(share), ghquota.Hint(licenseBudgetHint))
	}
	return ghBudget
}

// resetGitHubBudget starts a new budget; for tests.
func resetGitHubBudget() {
	ghBudgetMu.Lock()
	ghBudget = nil
	ghBudgetMu.Unlock()
	ghSeedOnce = sync.Once{}
	ghNoticeOnce = sync.Once{}
}

func inGitHubActions() bool { return os.Getenv("GITHUB_ACTIONS") == "true" }

// seedGitHubBudget asks GitHub for the quota left before the first lookup.
// GET /rate_limit does not count against it, so a run that starts below the
// floor spends nothing at all.
func seedGitHubBudget(token string) {
	ghSeedOnce.Do(func() {
		req, err := http.NewRequest(http.MethodGet, ghAPIBase+"rate_limit", nil)
		if err != nil {
			return
		}
		setGitHubHeaders(req, token)
		resp, err := ghHTTP.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return
		}
		var rl struct {
			Resources struct {
				Core struct {
					Limit     int `json:"limit"`
					Remaining int `json:"remaining"`
				} `json:"core"`
			} `json:"resources"`
		}
		if json.NewDecoder(resp.Body).Decode(&rl) == nil {
			githubBudget().Seed(rl.Resources.Core.Limit, rl.Resources.Core.Remaining)
		}
	})
}

// primeGitHubBudget seeds the budget before the first lookup, when there is a
// token to ask with.
func primeGitHubBudget() {
	if token := lookupToken(); token != "" {
		seedGitHubBudget(token)
	}
}

func setGitHubHeaders(req *http.Request, token string) {
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if token != "" {
		req.Header.Set("Authorization", "token "+token)
	}
}

// githubGet is a GET to the GitHub API with the lookup token, spent from the
// budget. The caller closes the body. It returns errGitHubBudget, without a
// request, once the budget has run out.
func githubGet(u string) (*http.Response, error) {
	token := lookupToken()
	primeGitHubBudget()
	b := githubBudget()
	if b.Exhausted() {
		return nil, errGitHubBudget
	}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	setGitHubHeaders(req, token)
	resp, err := ghHTTP.Do(req)
	if err != nil {
		return nil, err
	}
	b.ObserveHTTP(resp)
	return resp, nil
}

// reportGitHubLookups says what a batch of lookups cost. Inside GitHub Actions
// every batch that made a request says so, which is how a run's logs show what
// each job spent; anywhere, a batch the budget cut short says what it left
// unchecked, once per process.
func reportGitHubLookups(repos, spent, notChecked int) {
	b := githubBudget()
	if inGitHubActions() && spent > 0 {
		left := "quota not reported"
		if n, known := b.Remaining(); known {
			l, _ := b.Limit()
			left = fmt.Sprintf("%d of %d left", n, l)
		}
		fmt.Fprintf(noticeOut, "GitHub licence lookups: %d requests for %d repositories (%s)\n", spent, repos, left)
	}
	if b.Exhausted() && notChecked > 0 {
		ghNoticeOnce.Do(func() {
			fmt.Fprintf(noticeOut, "warning: GitHub licence lookups: %d of %d repositories not checked. %s\n",
				notChecked, repos, b.Reason())
		})
	}
}

// renderGHJQ is what gh prints for expr over body (see jqLine), each result
// on its own line.
func renderGHJQ(body []byte, expr string) ([]byte, error) {
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	switch expr {
	case jqSPDX:
		var v any
		if m, ok := doc.(map[string]any); ok {
			switch lic := m["license"].(type) {
			case map[string]any:
				v = lic["spdx_id"]
			case nil:
			default:
				return nil, errors.New("jq: cannot index license")
			}
		} else if doc != nil {
			return nil, errors.New("jq: cannot index document")
		}
		return jqLine(v)
	case jqContent:
		var v any
		if m, ok := doc.(map[string]any); ok {
			v = m["content"]
		} else if doc != nil {
			return nil, errors.New("jq: cannot index document")
		}
		return jqLine(v)
	case jqLicDir:
		arr, ok := doc.([]any)
		if !ok {
			return nil, errors.New("jq: cannot iterate document")
		}
		var b strings.Builder
		for _, e := range arr {
			m, ok := e.(map[string]any)
			if !ok {
				return nil, errors.New("jq: cannot index entry")
			}
			name, ok := m["name"].(string)
			if !ok {
				return nil, errors.New("jq: test on a non-string")
			}
			if licenseDirFilter.MatchString(name) {
				b.WriteString(name)
				b.WriteByte('\n')
			}
		}
		return []byte(b.String()), nil
	}
	return nil, errors.New("unsupported expression")
}

// jqLine prints one jq result as gh does: a string raw, null as an empty line,
// anything else as JSON.
func jqLine(v any) ([]byte, error) {
	if v == nil {
		return []byte("\n"), nil
	}
	if s, ok := v.(string); ok {
		return []byte(s + "\n"), nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
