package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"github.com/Vulnetix/vdb-sca-match/parse"

	"github.com/vulnetix/cli/v3/internal/scan"
)

// Runner answers one hook invocation.
type Runner struct {
	Policy Policy
	Lookup Lookup
	// Root is the repository the hook is running in.
	Root string
}

// Run routes a payload to whatever has something to say about it.
//
// Every path that cannot reach an answer returns Silent. A hook sits between an
// agent and the tool it asked to run: an error here would interrupt work over a
// problem the user did not cause and cannot act on.
func (r Runner) Run(ctx context.Context, p Payload) Response {
	if !r.Policy.Active() {
		return Response{Event: p.HookEventName, Decision: Silent}
	}

	switch p.HookEventName {
	case EventPreToolUse:
		return r.preToolUse(ctx, p)
	case EventSessionStart, EventUserPromptSubmit:
		return r.sessionContext(ctx, p)
	default:
		return Response{Event: p.HookEventName, Decision: Silent}
	}
}

func (r Runner) preToolUse(ctx context.Context, p Payload) Response {
	silent := Response{Event: EventPreToolUse, Decision: Silent}

	var candidates []Candidate

	switch {
	case isShellTool(p.ToolName):
		// One shell command is one of two questions, never both: `git commit`
		// records a change, `npm i` adds a dependency. Asking the change guard
		// first means a commit never pays for a dependency lookup that has
		// nothing to look at.
		if kind, _ := classifyGitCommand(p.Command()); kind != changeNone {
			return r.changeGuard(ctx, p)
		}
		candidates = ParseInstallCommand(p.Command())
	case isWriteTool(p.ToolName):
		candidates = r.manifestCandidates(p)
	}

	if len(candidates) == 0 {
		return silent
	}
	if r.Lookup == nil {
		return silent
	}

	return EvaluateDependency(r.Policy, r.Lookup.Assess(ctx, candidates))
}

// manifestCandidates recovers the dependencies an edit would add or change.
//
// Only what the edit introduces is assessed. A manifest that already declares
// forty packages is not forty things the agent just decided; re-reporting them
// on every edit is the noise that gets a guard switched off.
func (r Runner) manifestCandidates(p Payload) []Candidate {
	target := p.EditTarget()
	if target == "" {
		return nil
	}

	info, ok := manifestInfoFor(target)
	if !ok {
		return nil
	}

	before := readManifest(target)
	after, ok := proposedContent(p, before)
	if !ok {
		return nil
	}

	rel := relativeTo(r.Root, target)

	afterPkgs, err := parse.ParseManifest([]byte(after), info.Type, rel)
	if err != nil || len(afterPkgs) == 0 {
		// An unparseable proposal is not a verdict. The edit may be mid-write,
		// or the format may be one this build does not read; either way there is
		// nothing to say.
		return nil
	}

	existing := map[string]string{}
	if before != "" {
		if beforePkgs, err := parse.ParseManifest([]byte(before), info.Type, rel); err == nil {
			for _, pkg := range beforePkgs {
				existing[pkgKey(pkg.Name, pkg.Ecosystem)] = pkg.Version
			}
		}
	}

	var out []Candidate
	for _, pkg := range afterPkgs {
		key := pkgKey(pkg.Name, pkg.Ecosystem)
		if prev, ok := existing[key]; ok && prev == pkg.Version {
			continue
		}
		out = append(out, Candidate{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: pkg.Ecosystem,
			Manager:   info.Type,
		})
	}
	return out
}

// proposedContent reconstructs what the file would contain after the edit.
//
// A whole-file write carries its own content. A partial edit carries the
// replacement, so the current file supplies the rest; when the text being
// replaced is not present the reconstruction would be a guess, and a guess is
// not worth interrupting anybody over.
func proposedContent(p Payload, before string) (string, bool) {
	var in EditInput
	if len(p.ToolInput) == 0 {
		return "", false
	}
	if err := json.Unmarshal(p.ToolInput, &in); err != nil {
		return "", false
	}

	if in.Content != "" {
		return in.Content, true
	}
	if in.NewString == "" {
		return "", false
	}
	if in.OldString == "" {
		return in.NewString, before == ""
	}
	if !strings.Contains(before, in.OldString) {
		return "", false
	}
	return strings.Replace(before, in.OldString, in.NewString, 1), true
}

func readManifest(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// manifestInfoFor reports whether a path is a dependency manifest this build
// can parse, and how.
func manifestInfoFor(path string) (scan.ManifestInfo, bool) {
	info, ok := scan.DetectManifest(filepath.Base(path))
	if !ok || info == nil {
		return scan.ManifestInfo{}, false
	}
	return *info, true
}

func relativeTo(root, path string) string {
	if root == "" {
		return filepath.ToSlash(path)
	}
	if rel, err := filepath.Rel(root, path); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(path)
}

// isShellTool reports whether a tool name is a host's shell. Hosts spell it
// differently and a new one should not silently stop the guard, so the match is
// on what the name contains rather than an exact list.
func isShellTool(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "bash", "shell", "run_terminal_cmd", "terminal", "execute_command", "run_command":
		return true
	}
	return strings.Contains(n, "shell") || strings.Contains(n, "bash") || strings.Contains(n, "terminal")
}

// isWriteTool reports whether a tool name writes a file.
func isWriteTool(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "edit", "write", "multiedit", "str_replace_editor", "create_file", "apply_patch", "update_file":
		return true
	}
	return strings.Contains(n, "edit") || strings.Contains(n, "write") || strings.Contains(n, "patch")
}
