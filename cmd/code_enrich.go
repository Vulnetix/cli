package cmd

// What the rule engine does not record and the terminal report needs: when a
// secret entered the history (git blame) and which resource, image or service a
// finding sits in. Both are read here, once, after the scan; the engine, SARIF,
// JSON and every gate never see them.

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/vulnetix/cli/v3/internal/report"
)

// blameLimit bounds the git calls a secrets report makes. Each is cheap, but a
// repository with thousands of generic-key hits must not turn a scan into a
// blame run; the rest are shown without a history, which reads "unknown".
const (
	blameLimit   = 200
	blameTimeout = 20 * time.Second
)

// enrichCodeReport fills in what the labelled report needs.
func enrichCodeReport(cr *report.CodeReport, root string) {
	switch strings.ToLower(cr.Label) {
	case "secrets":
		blameSecrets(cr, root)
	case "iac", "container", "containers":
		findResources(cr, root)
	}
}

// historyPrefix marks a secrets finding in a past commit: the scan reads old
// versions of files as "__git_history__/<short-sha>/<path>".
const historyPrefix = "__git_history__/"

// blameSecrets asks git when each secret's line was committed. A file git does
// not track, or a line not yet committed, is "not committed". When there is no
// repository nothing is asked, and Blamed stays false: no history is not a
// clean history. A copy found in a past commit is committed by definition.
func blameSecrets(cr *report.CodeReport, root string) {
	if root == "" {
		root = "."
	}
	ctx, cancel := context.WithTimeout(context.Background(), blameTimeout)
	defer cancel()
	inRepo := false
	if out, err := exec.CommandContext(ctx, "git", "-C", root, "rev-parse", "--is-inside-work-tree").Output(); err == nil && strings.TrimSpace(string(out)) == "true" {
		inRepo = true
	}
	asked := 0
	times := map[string]time.Time{}
	for i := range cr.Findings {
		f := &cr.Findings[i]
		if rest, ok := strings.CutPrefix(f.Path, historyPrefix); ok {
			sha, path, _ := strings.Cut(rest, "/")
			if sha == "loose" {
				sha, _, _ = strings.Cut(path, "/")
				path = "(unreachable git object " + sha + ")"
			}
			f.Path, f.InHistory, f.Blamed, f.Committed, f.Commit = path, true, true, true, sha
			if at, seen := times[sha]; seen {
				f.CommittedAt = at
			} else if inRepo && ctx.Err() == nil {
				at := commitTime(ctx, root, sha)
				times[sha], f.CommittedAt = at, at
			}
			continue
		}
		if !inRepo || f.Line <= 0 || asked >= blameLimit || ctx.Err() != nil {
			continue
		}
		asked++
		sha, at, ok := blameLine(ctx, root, f.Path, f.Line)
		f.Blamed = true
		if ok {
			f.Committed, f.Commit, f.CommittedAt = true, sha, at
		}
	}
}

// commitTime is when a commit was made, or the zero time when git cannot say.
func commitTime(ctx context.Context, root, sha string) time.Time {
	out, err := exec.CommandContext(ctx, "git", "-C", root, "show", "-s", "--format=%ct", sha).Output()
	if err != nil {
		return time.Time{}
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(out)), 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(n, 0)
}

// blameLine returns the commit that last wrote a line. ok is false when the
// line is not committed: git has no such path in HEAD, or reports the all-zero
// commit it uses for working-tree changes.
func blameLine(ctx context.Context, root, path string, line int) (sha string, at time.Time, ok bool) {
	rng := strconv.Itoa(line) + "," + strconv.Itoa(line)
	out, err := exec.CommandContext(ctx, "git", "-C", root, "blame", "--porcelain", "-L", rng, "--", path).Output()
	if err != nil {
		return "", time.Time{}, false
	}
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		text := sc.Text()
		switch {
		case sha == "" && len(text) >= 40:
			fields := strings.Fields(text)
			if len(fields[0]) != 40 {
				return "", time.Time{}, false
			}
			if strings.Trim(fields[0], "0") == "" {
				return "", time.Time{}, false
			}
			sha = fields[0][:12]
		case strings.HasPrefix(text, "committer-time "):
			if n, err := strconv.ParseInt(strings.TrimPrefix(text, "committer-time "), 10, 64); err == nil {
				at = time.Unix(n, 0)
			}
		}
	}
	if sha == "" || at.IsZero() {
		return "", time.Time{}, false
	}
	return sha, at, true
}

var (
	reTFResource = regexp.MustCompile(`^\s*(resource|data)\s+"([^"]+)"\s+"([^"]+)"`)
	reTFModule   = regexp.MustCompile(`^\s*module\s+"([^"]+)"`)
	reTFOther    = regexp.MustCompile(`^\s*(variable|output|provider|locals|terraform)\b`)
	reComposeSvc = regexp.MustCompile(`^  ([A-Za-z0-9][A-Za-z0-9_.-]*):\s*(#.*)?$`)
	reFrom       = regexp.MustCompile(`(?i)^\s*FROM\s+(\S+)`)
)

// findResources names what each finding sits in, reading each file once.
func findResources(cr *report.CodeReport, root string) {
	cache := map[string][]string{}
	for i := range cr.Findings {
		f := &cr.Findings[i]
		if f.Resource != "" || f.Path == "" {
			continue
		}
		lines, ok := cache[f.Path]
		if !ok {
			lines = readLines(filepath.Join(root, f.Path))
			cache[f.Path] = lines
		}
		if lines == nil {
			continue
		}
		f.Resource, f.ResourceLine = resourceAt(f.Path, lines, f.Line)
	}
}

func readLines(path string) []string {
	st, err := os.Stat(path)
	if err != nil || st.IsDir() || st.Size() > 2<<20 {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
}

// resourceAt returns the resource enclosing a 1-based line and the line it
// starts on, or "" when the file has no such notion.
func resourceAt(path string, lines []string, line int) (string, int) {
	base := strings.ToLower(filepath.Base(path))
	switch {
	case strings.HasSuffix(base, ".tf"), strings.HasSuffix(base, ".hcl"), strings.HasSuffix(base, ".tfvars"):
		return terraformResource(lines, line)
	case strings.HasSuffix(base, ".yaml"), strings.HasSuffix(base, ".yml"):
		return yamlResource(lines, line)
	case strings.HasPrefix(base, "dockerfile"), strings.HasSuffix(base, ".dockerfile"), strings.HasPrefix(base, "containerfile"):
		return dockerStage(lines)
	}
	return "", 0
}

func terraformResource(lines []string, line int) (string, int) {
	for i := min(line, len(lines)) - 1; i >= 0; i-- {
		l := lines[i]
		if m := reTFResource.FindStringSubmatch(l); m != nil {
			if m[1] == "data" {
				return "data." + m[2] + "." + m[3], i + 1
			}
			return m[2] + "." + m[3], i + 1
		}
		if m := reTFModule.FindStringSubmatch(l); m != nil {
			return "module." + m[1], i + 1
		}
		if reTFOther.MatchString(l) {
			return "", 0
		}
	}
	return "", 0
}

// yamlResource reads a Kubernetes object (kind and metadata.name of the
// document the line is in) or a Compose service.
func yamlResource(lines []string, line int) (string, int) {
	if line <= 0 || line > len(lines) {
		return "", 0
	}
	start, end := 0, len(lines)
	for i := line - 1; i >= 0; i-- {
		if strings.HasPrefix(lines[i], "---") {
			start = i + 1
			break
		}
	}
	for i := line; i < len(lines); i++ {
		if strings.HasPrefix(lines[i], "---") {
			end = i
			break
		}
	}
	doc := lines[start:end]
	var kind, name string
	kindLine, inMeta, inServices := 0, false, false
	for i, l := range doc {
		switch {
		case strings.HasPrefix(l, "kind:"):
			kind, kindLine = unquote(strings.TrimPrefix(l, "kind:")), start+i+1
		case strings.HasPrefix(l, "metadata:"):
			inMeta = true
		case inMeta && strings.HasPrefix(l, "  name:") && name == "":
			name = unquote(strings.TrimPrefix(l, "  name:"))
		case strings.HasPrefix(l, "services:"):
			inServices = true
		case l != "" && !strings.HasPrefix(l, " ") && !strings.HasPrefix(l, "#"):
			if !strings.HasPrefix(l, "metadata:") {
				inMeta = false
			}
			if !strings.HasPrefix(l, "services:") {
				inServices = false
			}
		}
	}
	if inServices || hasTopLevel(doc, "services:") {
		for i := line - 1; i >= start; i-- {
			if m := reComposeSvc.FindStringSubmatch(lines[i]); m != nil {
				return "service " + m[1], i + 1
			}
		}
	}
	if kind != "" && name != "" {
		return kind + "/" + name, kindLine
	}
	return "", 0
}

func hasTopLevel(doc []string, key string) bool {
	for _, l := range doc {
		if strings.HasPrefix(l, key) {
			return true
		}
	}
	return false
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, " #"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	return strings.Trim(s, `"'`)
}

// dockerStage names a Dockerfile by its last FROM: the image that ships.
func dockerStage(lines []string) (string, int) {
	for i := len(lines) - 1; i >= 0; i-- {
		if m := reFrom.FindStringSubmatch(lines[i]); m != nil {
			return "FROM " + m[1], i + 1
		}
	}
	return "", 0
}
