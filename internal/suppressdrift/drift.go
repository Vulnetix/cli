// Package suppressdrift relocates code-anchored suppressions (nosec directives
// and file/line ignore rules) as the code they pin to moves through git
// history. Given the snippet a rule was created against, it finds where that
// snippet now lives — following file renames and line shifts via go-git blame
// and tree diffs — so the stored file path and line number stay accurate. When
// the snippet is gone from the current tree the rule is flagged for
// auto-deactivation.
package suppressdrift

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// storeErrStop short-circuits a go-git ForEach without signalling a real error.
var storeErrStop = errors.New("stop")

// Anchor is one suppression to relocate. Snippet is the code the rule is pinned
// to; FilePath/LineNumber are its last-known location.
type Anchor struct {
	Key        string // caller correlation key (e.g. fingerprint or uuid)
	FilePath   string
	LineNumber int
	Snippet    string
}

// Result is the reconciled location of an Anchor.
type Result struct {
	Key      string
	FilePath string // current path (may differ from Anchor.FilePath on rename)
	Line     int    // current 1-based line
	Commit   string // commit that last touched the anchored line (best-effort)
	Gone     bool   // snippet not found anywhere in the working tree
	Moved    bool   // path or line changed from the Anchor
}

// maxTreeFiles bounds the full-tree content scan so a huge repo cannot make a
// single scan pathological. Matches gitctx's history cap in spirit.
const maxTreeFiles = 20000

// Reconcile relocates every anchor against the git repo rooted at repoRoot.
// On any git error it returns (nil, err) and the caller should fall back to the
// on-disk snippet check — drift tracking is best-effort, never fatal.
func Reconcile(repoRoot string, anchors []Anchor) ([]Result, error) {
	repo, err := git.PlainOpen(repoRoot)
	if err != nil {
		return nil, err
	}
	head, err := repo.Head()
	if err != nil {
		return nil, err
	}
	headCommit, err := repo.CommitObject(head.Hash())
	if err != nil {
		return nil, err
	}
	tree, err := headCommit.Tree()
	if err != nil {
		return nil, err
	}

	out := make([]Result, 0, len(anchors))
	for _, a := range anchors {
		out = append(out, relocate(repoRoot, repo, headCommit, tree, a))
	}
	return out, nil
}

func relocate(repoRoot string, repo *git.Repository, head *object.Commit, tree *object.Tree, a Anchor) Result {
	res := Result{Key: a.Key, FilePath: a.FilePath, Line: a.LineNumber}
	needle := firstMeaningfulLine(a.Snippet)
	if needle == "" {
		// Nothing to relocate against; leave as-is rather than guess.
		return res
	}

	// 1) Fast path: still in the recorded file (working tree), closest to the
	//    recorded line.
	if line, ok := locateOnDisk(repoRoot, a.FilePath, needle, a.LineNumber); ok {
		res.Line = line
		res.Moved = line != a.LineNumber
		res.Commit = blameLineCommit(head, a.FilePath, line)
		return res
	}

	// 2) The recorded file is gone/renamed. Find the file that now carries the
	//    needle: prefer a git rename of the old path, else a full-tree scan.
	newPath := ""
	if rp := followRename(repo, head, a.FilePath, needle); rp != "" {
		newPath = rp
	} else if fp := scanTreeForNeedle(tree, needle); fp != "" {
		newPath = fp
	}
	if newPath != "" {
		if line, ok := locateOnDisk(repoRoot, newPath, needle, a.LineNumber); ok {
			res.FilePath = newPath
			res.Line = line
			res.Moved = true
			res.Commit = blameLineCommit(head, newPath, line)
			return res
		}
	}

	// 3) Not found anywhere → the anchor is gone.
	res.Gone = true
	return res
}

// firstMeaningfulLine returns the first non-blank, trimmed line of a snippet —
// the distinctive needle used to relocate it.
func firstMeaningfulLine(snippet string) string {
	for _, ln := range strings.Split(snippet, "\n") {
		if t := strings.TrimSpace(ln); t != "" {
			return t
		}
	}
	return ""
}

// locateOnDisk reads the working-tree file and returns the 1-based line whose
// (trimmed) content contains needle, preferring the match closest to hintLine.
func locateOnDisk(repoRoot, relPath, needle string, hintLine int) (int, bool) {
	if relPath == "" {
		return 0, false
	}
	p := relPath
	if !filepath.IsAbs(p) {
		p = filepath.Join(repoRoot, relPath)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return 0, false
	}
	return matchClosest(strings.Split(string(data), "\n"), needle, hintLine)
}

// scanTreeForNeedle returns the first tree file whose content carries the
// needle. Bounded by maxTreeFiles.
func scanTreeForNeedle(tree *object.Tree, needle string) string {
	found := ""
	count := 0
	_ = tree.Files().ForEach(func(f *object.File) error {
		if found != "" || count >= maxTreeFiles {
			return storeErrStop
		}
		count++
		if bin, err := f.IsBinary(); err != nil || bin {
			return nil
		}
		contents, err := f.Contents()
		if err != nil {
			return nil
		}
		if _, ok := matchClosest(strings.Split(contents, "\n"), needle, 0); ok {
			found = f.Name
			return storeErrStop
		}
		return nil
	})
	return found
}

// followRename walks recent history looking for a commit that renamed oldPath;
// it returns the path the content moved to at HEAD, or "" when no rename is
// found. Uses tree diffs (the same primitive as internal/secretscan history).
func followRename(repo *git.Repository, head *object.Commit, oldPath, needle string) string {
	if oldPath == "" {
		return ""
	}
	iter, err := repo.Log(&git.LogOptions{From: head.Hash})
	if err != nil {
		return ""
	}
	defer iter.Close()

	cur := oldPath
	steps := 0
	const maxSteps = 200
	newest := ""
	_ = iter.ForEach(func(c *object.Commit) error {
		steps++
		if steps > maxSteps {
			return storeErrStop
		}
		parent, perr := c.Parent(0)
		if perr != nil {
			return nil
		}
		ct, e1 := c.Tree()
		pt, e2 := parent.Tree()
		if e1 != nil || e2 != nil {
			return nil
		}
		changes, e3 := object.DiffTree(pt, ct)
		if e3 != nil {
			return nil
		}
		for _, ch := range changes {
			// A rename shows as From=old path, To=new path. Track our path
			// forward: if the child (To) is our current name, the parent (From)
			// is where it came from — but we want the newest name, so record the
			// first (newest) To that carries our needle.
			if ch.To.Name != "" && ch.From.Name != "" && ch.From.Name != ch.To.Name {
				if ch.From.Name == cur || ch.To.Name == cur {
					if newest == "" {
						newest = ch.To.Name
					}
					cur = ch.To.Name
				}
			}
		}
		return nil
	})
	if newest != "" && newest != oldPath {
		return newest
	}
	return ""
}

// blameLineCommit returns the short hash of the commit that last touched the
// given 1-based line of path at commit c. Best-effort: "" on any error.
func blameLineCommit(c *object.Commit, path string, line int) string {
	if path == "" || line <= 0 {
		return ""
	}
	br, err := git.Blame(c, path)
	if err != nil || br == nil {
		return ""
	}
	if line-1 < 0 || line-1 >= len(br.Lines) {
		return ""
	}
	h := br.Lines[line-1].Hash.String()
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// matchClosest returns the 1-based line index whose trimmed content contains
// needle, preferring the one nearest hintLine (0 = no hint).
func matchClosest(lines []string, needle string, hintLine int) (int, bool) {
	best := -1
	bestDist := 1 << 30
	for i, ln := range lines {
		if !strings.Contains(strings.TrimSpace(ln), needle) {
			continue
		}
		n := i + 1
		dist := n - hintLine
		if dist < 0 {
			dist = -dist
		}
		if hintLine == 0 {
			return n, true
		}
		if dist < bestDist {
			bestDist = dist
			best = n
		}
	}
	if best > 0 {
		return best, true
	}
	return 0, false
}
