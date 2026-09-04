package agent

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vulnetix/cli/v3/internal/sast"
)

// changeGuardBudget bounds the whole change guard.
//
// Shorter than the dependency guard's, because this one runs on `git commit`,
// which people type constantly and expect to be instant. Overrunning it yields
// no verdict rather than a late one.
const changeGuardBudget = 8 * time.Second

// changeGuardMaxFiles and changeGuardMaxBytes cap how much of a change is read.
//
// A commit is normally a handful of files. The caps exist for the ones that are
// not — a vendored tree landing in one commit, a generated bundle, a first push
// of an entire repository — where reading everything would blow the budget and
// deliver nothing. When a cap bites, the guard says so rather than reporting
// "no secrets found" about a change it only partly read.
const (
	changeGuardMaxFiles = 400
	changeGuardMaxBytes = 8 << 20
)

// changeKind is which git operation is about to run.
type changeKind int

const (
	changeNone changeKind = iota
	changeCommit
	changePush
)

// changeGuard answers whether the change about to be recorded carries a secret.
//
// Scope is deliberately narrow. This is not "scan the repository on commit":
// it reads only what the command in front of it would actually record, so a
// repository with a pre-existing finding is not re-reported on every commit.
// That is the same discipline the dependency guard applies to a manifest.
func (r Runner) changeGuard(ctx context.Context, p Payload) Response {
	silent := Response{Event: p.HookEventName, Decision: Silent}

	kind, alsoUnstaged := classifyGitCommand(p.Command())
	if kind == changeNone {
		return silent
	}

	// Nothing in the policy asks about this change, so there is nothing to
	// spend the budget on.
	if r.Policy.ChangeGuard.Decide(SignalSecret) == Silent {
		return silent
	}

	ctx, cancel := context.WithTimeout(ctx, changeGuardBudget)
	defer cancel()

	docs, truncated := r.changedDocuments(ctx, kind, alsoUnstaged)
	if len(docs) == 0 {
		return silent
	}

	findings, err := scanForSecrets(ctx, r.Root, docs)
	if err != nil {
		// An engine that could not run has not cleared the change. Saying
		// nothing is the only honest outcome, and it is also the safe one for
		// the person committing: a guard that fails closed on its own
		// unavailability blocks work for a reason nobody can act on.
		return silent
	}
	if len(findings) == 0 {
		return silent
	}

	decision := r.Policy.ChangeGuard.Decide(SignalSecret)

	return Response{
		Event:    p.HookEventName,
		Decision: decision,
		Message:  renderSecretFindings(kind, findings, truncated, decision),
	}
}

// classifyGitCommand reports which git operation a shell command would run.
//
// It also reports whether the commit would sweep in unstaged changes to tracked
// files, because `git commit -a` records more than `git diff --cached` shows and
// a guard that missed that would clear a change it never read.
func classifyGitCommand(command string) (changeKind, bool) {
	kind := changeNone
	alsoUnstaged := false

	for _, segment := range splitSegments(command) {
		fields := strings.Fields(segment)
		if len(fields) < 2 {
			continue
		}

		// `git`, `/usr/bin/git`, and `git -C dir commit` all have to match, so
		// find the subcommand rather than assuming it is the second field.
		if path.Base(fields[0]) != "git" {
			continue
		}

		sub, rest := gitSubcommand(fields[1:])
		switch sub {
		case "commit":
			kind = changeCommit
			for _, f := range rest {
				if isGitCommitAllFlag(f) {
					alsoUnstaged = true
				}
			}
		case "push":
			// A commit in the same command line wins: it is the change being
			// created, and the push that follows carries it.
			if kind == changeNone {
				kind = changePush
			}
		}
	}

	return kind, alsoUnstaged
}

// gitSubcommand skips git's own options to find the subcommand.
//
// `git -C path commit` and `git --git-dir=.git push` are both ordinary, and
// treating the first field after `git` as the subcommand misses them.
func gitSubcommand(args []string) (string, []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") {
			return a, args[i+1:]
		}
		// The handful of git options that take a separate value.
		switch a {
		case "-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path":
			i++
		}
	}
	return "", nil
}

// isGitCommitAllFlag reports whether a flag makes a commit include unstaged
// changes to tracked files. Short flags cluster, so `-am` counts.
func isGitCommitAllFlag(f string) bool {
	if f == "--all" {
		return true
	}
	if strings.HasPrefix(f, "--") || !strings.HasPrefix(f, "-") {
		return false
	}
	return strings.ContainsRune(f[1:], 'a')
}

// changedDocuments reads the content the operation would record, keyed by
// repository-relative path.
//
// The second return reports whether a cap stopped it short, so the caller can
// say the change was only partly read rather than implying it was cleared.
func (r Runner) changedDocuments(ctx context.Context, kind changeKind, alsoUnstaged bool) (map[string]string, bool) {
	if r.Root == "" {
		return nil, false
	}

	type source struct {
		paths []string
		// blobRef is the git revision to read a path's content from, or empty
		// to read the working tree.
		blobRef string
	}

	var sources []source

	switch kind {
	case changeCommit:
		sources = append(sources, source{
			paths:   r.git(ctx, "diff", "--cached", "--name-only", "-z", "--diff-filter=ACM"),
			blobRef: "", // ":path" — the staged blob; handled in readDoc.
		})
		if alsoUnstaged {
			sources = append(sources, source{
				paths: r.git(ctx, "diff", "--name-only", "-z", "--diff-filter=ACM"),
				// -a records the working tree, so that is what to read.
				blobRef: "worktree",
			})
		}
	case changePush:
		// With an upstream, the change is exactly what the remote has not seen.
		if paths := r.git(ctx, "diff", "--name-only", "-z", "--diff-filter=ACM", "@{upstream}..HEAD"); len(paths) > 0 {
			sources = append(sources, source{paths: paths, blobRef: "HEAD"})
			break
		}
		// Without one — a first push, or a branch with no tracking ref — there
		// is no baseline to diff against. Reading the whole committed tree is
		// the only way to answer at all, and a first push is exactly when a
		// secret that has been sitting in the branch finally leaves the machine.
		// The caps below are what keep that affordable.
		if r.git(ctx, "rev-parse", "--verify", "--quiet", "HEAD") == nil {
			return nil, false
		}
		sources = append(sources, source{
			paths:   r.git(ctx, "ls-tree", "-r", "--name-only", "-z", "HEAD"),
			blobRef: "HEAD",
		})
	}

	docs := make(map[string]string)
	total := 0
	truncated := false

	for _, src := range sources {
		for _, rel := range src.paths {
			if rel == "" {
				continue
			}
			if _, seen := docs[rel]; seen {
				continue
			}
			if len(docs) >= changeGuardMaxFiles {
				truncated = true
				break
			}

			content, ok := r.readDoc(ctx, src.blobRef, rel)
			if !ok {
				continue
			}
			if total+len(content) > changeGuardMaxBytes {
				truncated = true
				break
			}

			docs[rel] = content
			total += len(content)
		}
	}

	return docs, truncated
}

// readDoc reads one path's content at the revision the operation would record.
func (r Runner) readDoc(ctx context.Context, blobRef, rel string) (string, bool) {
	var spec string
	switch blobRef {
	case "":
		spec = ":" + rel // the staged blob
	case "worktree":
		return readWorktreeFile(filepath.Join(r.Root, rel))
	default:
		spec = blobRef + ":" + rel
	}

	out, err := r.gitOutput(ctx, "show", spec)
	if err != nil {
		return "", false
	}
	// A binary blob is not something the secret rules read usefully, and
	// carrying it would spend the byte budget on noise.
	if isProbablyBinary(out) {
		return "", false
	}
	return string(out), true
}

// scanForSecrets runs only the secret rules, over only the supplied documents.
func scanForSecrets(ctx context.Context, root string, docs map[string]string) ([]sast.Finding, error) {
	modules, err := sast.LoadAllModules(sast.DefaultRulesFS, false, nil, "", io.Discard)
	if err != nil {
		return nil, fmt.Errorf("loading rules: %w", err)
	}

	// Overlay onto nothing: the input is the change, not the repository. Rules
	// that ask whether some other file exists will not fire, which is correct
	// here — this guard answers about the change in front of it.
	input := sast.Overlay(nil, docs)
	input.ScanRoot = root

	var session sast.Session
	report, err := session.Run(ctx, modules, []string{sast.KindSecrets}, input)
	if err != nil {
		return nil, err
	}
	if report == nil {
		return nil, nil
	}
	return report.Findings, nil
}

// renderSecretFindings writes the verdict the model receives.
//
// Written as a report about a change, never as an instruction. Claude Code
// labels injected hook text as "not something I'll act on" when it reads as a
// directive, so the text describes what was found and leaves the decision where
// it belongs.
func renderSecretFindings(kind changeKind, findings []sast.Finding, truncated bool, decision Decision) string {
	verb := "commit"
	if kind == changePush {
		verb = "push"
	}

	// Deterministic order: a hook that reports the same change differently on
	// two runs is one nobody can write a test against.
	sort.Slice(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.ArtifactURI != b.ArtifactURI {
			return a.ArtifactURI < b.ArtifactURI
		}
		if a.StartLine != b.StartLine {
			return a.StartLine < b.StartLine
		}
		return a.RuleID < b.RuleID
	})

	var b strings.Builder

	noun := "credential"
	if len(findings) != 1 {
		noun = "credentials"
	}
	fmt.Fprintf(&b, "Vulnetix: %d %s in the change this %s would record.\n\n",
		len(findings), noun, verb)

	shown := findings
	if len(shown) > 10 {
		shown = shown[:10]
	}
	for _, f := range shown {
		fmt.Fprintf(&b, "  %s:%d  %s", f.ArtifactURI, f.StartLine, f.RuleID)
		if msg := strings.TrimSpace(f.Message); msg != "" {
			fmt.Fprintf(&b, "  %s", msg)
		}
		b.WriteString("\n")
	}
	if len(findings) > len(shown) {
		fmt.Fprintf(&b, "  ...and %d more\n", len(findings)-len(shown))
	}

	b.WriteString("\n")
	if truncated {
		b.WriteString("Only part of the change was read, so this is not a clean bill of health for the rest.\n")
	}

	if decision == Block {
		b.WriteString("A committed credential is disclosed even if the commit is later amended, " +
			"so rotating it is part of the fix, not an alternative to it.")
	} else {
		b.WriteString("Reported, not blocked, per this repository's changeGuard policy.")
	}

	return b.String()
}

// git runs a git command that produces a NUL-separated path list.
func (r Runner) git(ctx context.Context, args ...string) []string {
	out, err := r.gitOutput(ctx, args...)
	if err != nil {
		return nil
	}
	var paths []string
	for _, p := range bytes.Split(out, []byte{0}) {
		if len(p) > 0 {
			paths = append(paths, string(p))
		}
	}
	return paths
}

// gitOutput runs one git command in the repository root.
func (r Runner) gitOutput(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = r.Root
	// git reads config from the environment; leaving it inherited is right, but
	// stderr is not, because a hook owns stdout and must not leak onto it.
	cmd.Stderr = io.Discard
	return cmd.Output()
}

// readWorktreeFile reads one working-tree file, refusing anything too large or
// binary to be worth handing to the secret rules.
func readWorktreeFile(abs string) (string, bool) {
	info, err := os.Stat(abs)
	if err != nil || info.IsDir() || info.Size() > changeGuardMaxBytes {
		return "", false
	}
	b, err := os.ReadFile(abs)
	if err != nil || isProbablyBinary(b) {
		return "", false
	}
	return string(b), true
}

// isProbablyBinary reports whether content is binary, by the same NUL-byte test
// git itself uses.
func isProbablyBinary(b []byte) bool {
	if len(b) > 8000 {
		b = b[:8000]
	}
	return bytes.IndexByte(b, 0) >= 0
}
