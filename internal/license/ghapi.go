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
	token := ghAuthToken()
	if token == "" {
		return nil, false, nil
	}
	req, rerr := http.NewRequest(http.MethodGet, ghAPIBase+path, nil)
	if rerr != nil {
		return nil, false, nil
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, derr := ghHTTP.Do(req)
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
