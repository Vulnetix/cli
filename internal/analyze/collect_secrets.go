package analyze

// Secrets in history: the two passes nothing else does.
//
// Content scanning of the working tree already exists (`vulnetix secrets`), and history-blob
// scanning exists in internal/secretscan. What nobody does — and what repolinter, alone among
// the surveyed tools, got right — is the other two places a secret hides:
//
//   - **Commit messages.** `git commit -m "temp fix, password is hunter2"`. No content scanner
//     will ever see this, because it is not in a file. It is in the object database forever,
//     and it is readable by anyone who can clone.
//   - **Filenames.** A committed-then-deleted `id_rsa`, `.env.production`, `credentials.json`.
//     The file is gone from HEAD, so a tree scan finds nothing; the blob is still reachable,
//     and so is the name, which is often all an attacker needs to know what to go looking for.
//
// The question this answers is not "is there a secret in the code" — it is "does a credential
// need rotating", and those have different answers. A secret removed in the next commit is
// still a secret that was published.

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/vulnetix/cli/v3/internal/sast"
)

// secretishNames are filenames that should never be committed. Matching is on the name alone,
// because that is the point: the file's contents are not needed to know it was a mistake.
var secretishNames = []*regexp.Regexp{
	regexp.MustCompile(`(?i)^id_(rsa|dsa|ecdsa|ed25519)$`),
	regexp.MustCompile(`(?i)^\.env(\..+)?$`),
	regexp.MustCompile(`(?i)^.*\.pem$`),
	regexp.MustCompile(`(?i)^.*\.p12$`),
	regexp.MustCompile(`(?i)^.*\.pfx$`),
	regexp.MustCompile(`(?i)^.*\.keystore$`),
	regexp.MustCompile(`(?i)^.*\.jks$`),
	regexp.MustCompile(`(?i)^credentials(\.json|\.yml|\.yaml)?$`),
	regexp.MustCompile(`(?i)^service-account.*\.json$`),
	regexp.MustCompile(`(?i)^\.npmrc$`),
	regexp.MustCompile(`(?i)^\.pypirc$`),
	regexp.MustCompile(`(?i)^\.netrc$`),
	regexp.MustCompile(`(?i)^secrets?\.(json|yml|yaml|env|txt)$`),
	regexp.MustCompile(`(?i)^.*\.key$`),
}

// messageSecrets look for a credential written into a commit message. Deliberately narrow:
// the word "password" in a message is usually someone describing a password field, not
// leaking one. What we want is an assignment — a word, a separator, and a value.
var messageSecrets = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)\b\s*[:=]\s*\S{6,}`),
	regexp.MustCompile(`(?i)\bAKIA[0-9A-Z]{16}\b`),                                       // AWS access key id
	regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,}\b`),                                 // GitHub token
	regexp.MustCompile(`(?i)\bxox[baprs]-[0-9A-Za-z-]{10,}\b`),                           // Slack
	regexp.MustCompile(`\b(sk|pk)_(live|test)_[0-9a-zA-Z]{16,}\b`),                       // Stripe
	regexp.MustCompile(`(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----`),                         // a key, pasted into a message
	regexp.MustCompile(`(?i)\b(mongodb|postgres(?:ql)?|mysql|redis)://[^\s:]+:[^\s@]+@`), // a DSN with a password in it
}

// maxHistoryCommitsForSecrets bounds the walk. Declared when it bites.
const maxHistoryCommitsForSecrets = 5000

type secretFinding struct {
	rule    string
	message string
	sha     string
	path    string
}

// collectSecrets scans commit messages and the names of every file ever committed, and
// appends its findings to the SARIF the trust collector started.
func collectSecrets(b *Builder, repo *git.Repository, git2 *gitStats, existing []sast.Finding, rules []sast.RuleMetadata, pr reporter) ([]sast.Finding, []sast.RuleMetadata) {
	if repo == nil {
		b.Unmeasured(Metric{
			ID: "security.secrets.history", Family: "security", Name: "Secrets in git history",
			Definition: "Credentials found in commit messages or in the names of files that were ever committed.",
			Unit:       "count",
		}, "Not a git repository, so there is no history to scan.")

		return existing, rules
	}

	head, err := repo.Head()
	if err != nil {
		return existing, rules
	}
	iter, err := repo.Log(&git.LogOptions{From: head.Hash()})
	if err != nil {
		return existing, rules
	}
	defer iter.Close()

	var findings []secretFinding
	seenPath := map[string]bool{}
	walked := 0
	truncated := false

	_ = iter.ForEach(func(c *object.Commit) error {
		if walked >= maxHistoryCommitsForSecrets {
			truncated = true

			return errStopWalk
		}
		walked++
		if walked%100 == 0 {
			pr.Stage("Searching history for secrets (" + plural(walked, "commit", "commits") + ")")
		}

		// Pass 1 — the commit message. Nothing else looks here.
		for _, re := range messageSecrets {
			if m := re.FindString(c.Message); m != "" {
				findings = append(findings, secretFinding{
					rule:    "secret-in-commit-message",
					message: fmt.Sprintf("A credential appears in the message of commit %s. It is in the object database permanently and is readable by anyone who can clone the repository — removing it from the file it was in does not remove it from here. Rotate the credential.", c.Hash.String()[:12]),
					sha:     c.Hash.String(),
				})

				break
			}
		}

		// Pass 2 — the names of the files in this commit. A file deleted in the next commit is
		// gone from HEAD and invisible to a tree scan; the name is still here, and the blob is
		// still reachable.
		files, ferr := c.Files()
		if ferr != nil {
			return nil
		}
		_ = files.ForEach(func(f *object.File) error {
			base := f.Name
			if i := strings.LastIndex(base, "/"); i >= 0 {
				base = base[i+1:]
			}
			for _, re := range secretishNames {
				if !re.MatchString(base) {
					continue
				}
				if seenPath[f.Name] {
					return nil
				}
				seenPath[f.Name] = true

				findings = append(findings, secretFinding{
					rule:    "secret-file-in-history",
					message: fmt.Sprintf("%s was committed. Even if it has since been deleted, the blob remains reachable in the object database and the credential it held must be treated as disclosed. Rotate it, and rewrite history if the repository is public.", f.Name),
					sha:     c.Hash.String(),
					path:    f.Name,
				})

				return nil
			}

			return nil
		})

		return nil
	})

	// Findings become SARIF results, alongside the policy breaches — one findings surface, not
	// two, so `analyze` shows up in Scanner Results like every other scan.
	base := len(existing)

	rules = append(rules,
		sast.RuleMetadata{
			ID: "secret-in-commit-message", Name: "Secret in a commit message",
			Description: "A credential written into a commit message. No content scanner looks here, and the message cannot be edited without rewriting history.",
			Severity:    "critical", Level: "error", Kind: "analyze",
			Tags: []string{"secret", "history"},
		},
		sast.RuleMetadata{
			ID: "secret-file-in-history", Name: "Secret file committed to history",
			Description: "A file whose name marks it as a credential was committed at some point. Deleting it does not unpublish it.",
			Severity:    "critical", Level: "error", Kind: "analyze",
			Tags: []string{"secret", "history"},
		},
	)

	refsByRule := map[string][]EvidenceRef{}
	for i, f := range findings {
		uri := f.path
		if uri == "" {
			uri = ".git"
		}
		existing = append(existing, sast.Finding{
			RuleID:      f.rule,
			Message:     f.message,
			Severity:    "critical",
			Level:       "error",
			ArtifactURI: uri,
			StartLine:   1,
		})
		refsByRule[f.rule] = append(refsByRule[f.rule], SARIFRef(base+i))
	}

	all := append(append([]EvidenceRef{}, refsByRule["secret-in-commit-message"]...),
		refsByRule["secret-file-in-history"]...)

	m := Metric{
		ID: "security.secrets.history", Family: "security", Name: "Secrets in git history",
		Definition: "Credentials found in commit messages, and files whose names mark them as credentials that were ever committed. This is not the same question as 'is there a secret in the code' — a secret removed in the next commit is still a secret that was published, and the answer determines whether something needs rotating.",
		Classification: &Classification{
			Label:      secretClass(len(all)),
			Thresholds: "0 = clean, any = rotate the credential",
		},
		References: []Reference{{
			Title: "repolinter git-grep-log / git-list-tree",
			URL:   "https://github.com/todogroup/repolinter",
		}},
	}

	if truncated {
		b.CountTruncated(m, all, 1, fmt.Sprintf(
			"history scan stopped at %d commits; older commits were not searched for secrets", maxHistoryCommitsForSecrets))
	} else {
		b.Count(m, all)
	}

	b.Count(Metric{
		ID: "security.secrets.commit_messages", Family: "security", Name: "Secrets in commit messages",
		Definition: "Credentials written into a commit message. No content scanner looks here, because the message is not a file.",
	}, refsByRule["secret-in-commit-message"])

	b.Count(Metric{
		ID: "security.secrets.committed_files", Family: "security", Name: "Secret files ever committed",
		Definition: "Files whose names mark them as credentials (private keys, .env, service-account JSON, keystores) that appear anywhere in history, whether or not they still exist at HEAD.",
	}, refsByRule["secret-file-in-history"])

	return existing, rules
}

func secretClass(n int) string {
	if n == 0 {
		return "clean"
	}

	return "rotate"
}
