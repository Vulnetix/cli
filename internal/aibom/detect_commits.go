package aibom

import (
	"errors"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/vulnetix/cli/v3/internal/cdx"
)

// defaultCommitScanMax bounds how many commits (from HEAD backwards) the commit
// pass inspects, keeping it fast on large histories.
const defaultCommitScanMax = 2000

var errCommitScanDone = errors.New("commit scan limit reached")

// detectCommits attributes git commits to AI agents whose commit_patterns match
// a commit's author/committer identity or message — e.g. a
// "Co-Authored-By: Claude <noreply@anthropic.com>" trailer, a "Claude-Session:"
// line, an agent bot author, or a "Generated with <tool>" marker. This catches
// agent usage that left no config/env/source trace in the working tree.
func (c *collector) detectCommits(root string, maxCommits int) {
	if maxCommits <= 0 {
		maxCommits = defaultCommitScanMax
	}
	// Skip entirely if no tool declares commit signatures.
	hasPatterns := false
	for i := range c.cat.Tools {
		if len(c.cat.Tools[i].Commits) > 0 {
			hasPatterns = true
			break
		}
	}
	if !hasPatterns {
		return
	}

	repo, err := git.PlainOpenWithOptions(root, &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return
	}
	head, err := repo.Head()
	if err != nil {
		return
	}
	iter, err := repo.Log(&git.LogOptions{From: head.Hash()})
	if err != nil {
		return
	}
	defer iter.Close()

	n := 0
	_ = iter.ForEach(func(commit *object.Commit) error {
		n++
		short := commit.Hash.String()
		if len(short) > 8 {
			short = short[:8]
		}
		// Haystack = author + committer identity + full message (trailers live in
		// the message). Patterns decide their own case-sensitivity via (?i).
		hay := commit.Author.Name + " <" + commit.Author.Email + ">\n" +
			commit.Committer.Name + " <" + commit.Committer.Email + ">\n" +
			commit.Message
		for i := range c.cat.Tools {
			t := &c.cat.Tools[i]
			for _, re := range t.Commits {
				if loc := re.FindStringIndex(hay); loc != nil {
					c.toolCommitHit(t.Def, short, commitSnippet(hay, loc))
					break // at most one hit per tool per commit
				}
			}
		}
		if n >= maxCommits {
			return errCommitScanDone
		}
		return nil
	})
}

func (c *collector) toolCommitHit(def ToolDef, shortSha, snippet string) {
	h := c.tool(def)
	h.methods["commit"] = true
	h.primary++
	h.counts["commits"]++
	if len(h.evidence) < maxEvidenceCollect {
		h.evidence = append(h.evidence, cdx.AIEvidence{
			Method: "commit", Category: "commit", Locator: shortSha, Snippet: snippet,
		})
	}
}

// commitSnippet renders the matched substring as a short, single-line marker.
func commitSnippet(s string, loc []int) string {
	m := strings.TrimSpace(strings.ReplaceAll(s[loc[0]:loc[1]], "\n", " "))
	if len(m) > 80 {
		m = m[:80]
	}
	return m
}
