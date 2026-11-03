package cmd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vulnetix/cli/v4/internal/platformiac"
)

// Where a scan's VEX comes from, beyond --vex-file:
//
//	--vex <path|dir|https URL>   repeatable; a URL is fetched for this run
//	VexSource documents          declared in .vulnetix/config: a `path` source is
//	                             read from disk and a `urls` source is fetched, so
//	                             a CI gate honours what the organization declared
//	                             without a second flag
//
// tea, s3 and git sources are fetched by the console, not here. Their
// statements are the console's rules, and an authenticated scan applies them
// from there with the documents (scanConsoleVEX in vex.go). An unauthenticated
// scan cannot; point --vex at the same documents to have it honour them.
//
// A declared source keeps the limits it was declared with. scope.repos applies
// the source only to those repositories; trust.allowedAuthors drops documents
// by anyone else. A source the CLI cannot honour exactly is skipped with a
// note, never applied more widely than declared.

const (
	// vexFetchMax is the largest VEX document fetched from a URL.
	vexFetchMax = 8 << 20
	// vexFetchTimeout bounds one fetch; a slow host costs the document, not the scan.
	vexFetchTimeout = 30 * time.Second
)

// vexSourceDecl is the part of a VexSource the scan reads.
type vexSourceDecl struct {
	Name           string
	Paths          []string
	URLs           []string
	Repos          []string
	AllowedAuthors []string
	Unsupported    string // tea, s3 or git: the console's
}

// vexSourceDecls reads the VexSource documents under root's config folder.
func vexSourceDecls(root string, notes io.Writer) []vexSourceDecl {
	docs, err := platformiac.Discover(platformiac.Options{Root: root})
	if err != nil {
		fmt.Fprintf(notes, "  warning: VexSource documents not read: %v\n", err)
		return nil
	}
	var out []vexSourceDecl
	for _, d := range docs {
		if d.Kind != "VexSource" {
			continue
		}
		m, _ := d.Value.(map[string]any)
		spec, _ := m["spec"].(map[string]any)
		decl := vexSourceDecl{Name: d.Name}
		if decl.Name == "" {
			decl.Name = "default"
		}
		if p, ok := spec["path"].(map[string]any); ok {
			if s, _ := p["path"].(string); s != "" {
				decl.Paths = append(decl.Paths, s)
			}
		}
		if us, ok := spec["urls"].([]any); ok {
			for _, u := range us {
				switch t := u.(type) {
				case string:
					decl.URLs = append(decl.URLs, t)
				case map[string]any:
					if s, _ := t["url"].(string); s != "" {
						decl.URLs = append(decl.URLs, s)
					}
				}
			}
		}
		for _, k := range []string{"tea", "s3", "git"} {
			if _, ok := spec[k]; ok {
				decl.Unsupported = k
			}
		}
		if sc, ok := spec["scope"].(map[string]any); ok {
			if rs, ok := sc["repos"].([]any); ok {
				for _, r := range rs {
					if s, _ := r.(string); s != "" {
						decl.Repos = append(decl.Repos, s)
					}
				}
			}
		}
		if tr, ok := spec["trust"].(map[string]any); ok {
			if as, ok := tr["allowedAuthors"].([]any); ok {
				for _, a := range as {
					if s, _ := a.(string); s != "" {
						decl.AllowedAuthors = append(decl.AllowedAuthors, s)
					}
				}
			}
		}
		out = append(out, decl)
	}
	return out
}

// repoInScope reports whether repo (owner/name, may be empty) is one a source
// is scoped to. A source with no scope.repos applies everywhere.
func repoInScope(scope []string, repo string) bool {
	if len(scope) == 0 {
		return true
	}
	for _, s := range scope {
		if repo != "" && strings.EqualFold(strings.TrimSuffix(s, ".git"), repo) {
			return true
		}
	}
	return false
}

// authorAllowed reports whether a document's author is trusted. An empty list
// trusts every author.
func authorAllowed(allowed []string, author string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, a := range allowed {
		if strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(author)) {
			return true
		}
	}
	return false
}

// fetchVEX downloads one https URL into dir and returns the file. The name
// comes from the URL's last segment so ingest and reports read sensibly.
func fetchVEX(ctx context.Context, raw, dir string, client *http.Client) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", fmt.Errorf("%s: only https URLs are fetched", raw)
	}
	ctx, cancel := context.WithTimeout(ctx, vexFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "vulnetix-cli/"+version)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("%s: %w", raw, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("%s: HTTP %d", raw, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, vexFetchMax+1))
	if err != nil {
		return "", fmt.Errorf("%s: %w", raw, err)
	}
	if len(data) > vexFetchMax {
		return "", fmt.Errorf("%s: over %d MiB", raw, vexFetchMax>>20)
	}
	name := path.Base(u.Path)
	if name == "" || name == "." || name == "/" {
		name = u.Host
	}
	if !strings.HasSuffix(strings.ToLower(name), ".json") {
		name += ".json"
	}
	f, err := os.CreateTemp(dir, "*-"+filepath.Base(name))
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return "", err
	}
	return f.Name(), nil
}

// expandVEXPaths turns a file or directory into the VEX files in it (one level
// deep, the same rule as vex.LoadAll), so each can be checked on its own.
func expandVEXPaths(p string) ([]string, error) {
	info, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{p}, nil
	}
	entries, err := os.ReadDir(p)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".json") {
			out = append(out, filepath.Join(p, e.Name()))
		}
	}
	sort.Strings(out)
	return out, nil
}

// vexInputsOptions are the inputs to resolveVEXInputs.
type vexInputsOptions struct {
	Explicit   []string // --vex-file and --vex values: files, directories, https URLs
	FromConfig bool     // also read the VexSource documents under Root
	Root       string
	Repo       string // owner/name of the scanned repository, "" when unknown
	Notes      io.Writer
	HTTP       *http.Client
}

// resolveVEXInputs returns the local VEX files a scan applies, and a cleanup
// for any it downloaded. Explicit entries are used as given (a URL that cannot
// be fetched is an error: the user asked for it). Declared sources are
// best effort and limited as declared.
func resolveVEXInputs(ctx context.Context, o vexInputsOptions) ([]string, func(), error) {
	noop := func() {}
	if o.Notes == nil {
		o.Notes = io.Discard
	}
	client := o.HTTP
	if client == nil {
		client = &http.Client{Timeout: vexFetchTimeout}
	}
	var tmp string
	cleanup := func() {
		if tmp != "" {
			_ = os.RemoveAll(tmp)
		}
	}
	tmpDir := func() (string, error) {
		if tmp == "" {
			d, err := os.MkdirTemp("", "vulnetix-vex-")
			if err != nil {
				return "", err
			}
			tmp = d
		}
		return tmp, nil
	}

	var paths []string
	for _, e := range o.Explicit {
		if strings.HasPrefix(strings.ToLower(e), "http://") {
			cleanup()
			return nil, noop, fmt.Errorf("--vex %s: only https URLs are fetched", e)
		}
		if strings.HasPrefix(strings.ToLower(e), "https://") {
			dir, err := tmpDir()
			if err != nil {
				cleanup()
				return nil, noop, err
			}
			f, err := fetchVEX(ctx, e, dir, client)
			if err != nil {
				cleanup()
				return nil, noop, fmt.Errorf("--vex: %w", err)
			}
			paths = append(paths, f)
			continue
		}
		paths = append(paths, e)
	}

	if o.FromConfig {
		for _, d := range vexSourceDecls(o.Root, o.Notes) {
			if d.Unsupported != "" {
				// The console holds this source's statements as rules, and an
				// authenticated scan reads them from there (scanConsoleVEX). Only an
				// unauthenticated one has to be told it is not applying them.
				if isUnauthenticatedScan() {
					fmt.Fprintf(o.Notes, "  note: VexSource/%s reads a %s source, which the console fetches; sign in (vulnetix auth login) to have a scan apply its statements, or pass its documents with --vex\n", d.Name, d.Unsupported)
				}
				continue
			}
			if !repoInScope(d.Repos, o.Repo) {
				continue
			}
			var candidates []string
			for _, p := range d.Paths {
				full := p
				if !filepath.IsAbs(p) {
					full = filepath.Join(o.Root, filepath.FromSlash(p))
					if _, err := os.Stat(full); err != nil {
						full = filepath.Join(o.Root, platformiac.ConfigDir, filepath.FromSlash(p))
					}
				}
				files, err := expandVEXPaths(full)
				if err != nil {
					fmt.Fprintf(o.Notes, "  warning: VexSource/%s: %v\n", d.Name, err)
					continue
				}
				candidates = append(candidates, files...)
			}
			for _, u := range d.URLs {
				dir, err := tmpDir()
				if err != nil {
					fmt.Fprintf(o.Notes, "  warning: VexSource/%s: %v\n", d.Name, err)
					continue
				}
				f, err := fetchVEX(ctx, u, dir, client)
				if err != nil {
					fmt.Fprintf(o.Notes, "  warning: VexSource/%s: %v\n", d.Name, err)
					continue
				}
				candidates = append(candidates, f)
			}
			for _, f := range candidates {
				author, err := vexDocumentAuthor(f)
				if err != nil {
					// Not VEX (a sibling SBOM or SARIF in a folder) or unreadable.
					continue
				}
				if !authorAllowed(d.AllowedAuthors, author) {
					fmt.Fprintf(o.Notes, "  note: VexSource/%s: %s is by %q, which trust.allowedAuthors does not allow; skipped\n", d.Name, filepath.Base(f), author)
					continue
				}
				paths = append(paths, f)
			}
		}
	}
	return dedupeStrings(paths), cleanup, nil
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
