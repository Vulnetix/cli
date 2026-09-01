package lsp

import (
	"path/filepath"
	"sync"
	"time"

	"github.com/vulnetix/cli/v3/internal/lsp/protocol"
	"github.com/vulnetix/cli/v3/internal/memory"
	"github.com/vulnetix/cli/v3/internal/suppress"
)

// vulnetixDirName is the per-repository state directory holding memory.yaml.
const vulnetixDirName = ".vulnetix"

// suppressionStore holds the active ignore rules for the workspace.
//
// Two sources, merged in one direction: rules from the editor's settings take
// precedence over the repository's memory.yaml. That ordering is what makes the
// setting useful — it exists so someone can silence a finding locally without
// committing a change to a file the whole team shares.
//
// The matcher itself is internal/suppress, the same one every scan pipeline
// uses, so a finding hidden in CI is hidden in the editor and vice versa.
type suppressionStore struct {
	mu  sync.Mutex
	set *suppress.Set
	// path is the memory file the rules were loaded from, kept so a watcher can
	// tell whether a changed file is the one that matters.
	path string
}

func newSuppressionStore() *suppressionStore {
	return &suppressionStore{}
}

// Reload rebuilds the rule set from the memory file and the editor settings.
//
// A missing or unreadable memory file is not an error: most repositories do not
// have one, and failing here would take suppression down entirely rather than
// falling back to the editor's own rules.
func (s *suppressionStore) Reload(root string, cfg Settings) {
	dir := memoryDir(root, cfg.MemoryPath)

	var rules []suppress.Rule
	if mem, err := memory.Load(dir); err == nil && mem != nil {
		rules = append(rules, suppress.FromMemory(mem.Suppressions)...)
	}

	// Editor rules are appended last but matched the same way; Match returns the
	// first rule that fits, and both sources produce the same verdict, so
	// ordering only decides which reason is reported.
	for _, r := range cfg.Suppressions {
		rules = append(rules, suppress.Rule{
			RuleID:    r.RuleID,
			FindingID: r.FindingID,
			FilePath:  r.FilePath,
			Reason:    r.Reason,
			IsActive:  true,
		})
	}

	s.mu.Lock()
	s.set = suppress.NewSet(rules, time.Now().Unix())
	s.path = filepath.Join(dir, memory.FileName)
	s.mu.Unlock()
}

// MemoryFile is the path being watched for external edits.
func (s *suppressionStore) MemoryFile() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.path
}

// Filter removes suppressed diagnostics, or demotes them to hints when the user
// asked to see what is being hidden.
//
// Demotion rather than a badge because a Hint is the one severity that stays
// out of the Problems panel's error and warning counts while remaining visible
// in the file — which is exactly what "show me what I silenced" means.
func (s *suppressionStore) Filter(relPath string, diags []protocol.Diagnostic, showSuppressed bool) []protocol.Diagnostic {
	s.mu.Lock()
	set := s.set
	s.mu.Unlock()

	if set.Empty() {
		return diags
	}

	out := make([]protocol.Diagnostic, 0, len(diags))
	for _, d := range diags {
		rule, matched := set.Match(suppress.Finding{
			Category:  categoryOf(d.Source),
			RuleID:    d.Code,
			FindingID: findingIDOf(d),
			FilePath:  relPath,
		})
		if !matched {
			out = append(out, d)
			continue
		}
		if !showSuppressed {
			continue
		}
		d.Severity = protocol.SeverityHint
		if reason := rule.Reason; reason != "" {
			d.Message = d.Message + " (suppressed: " + reason + ")"
		} else {
			d.Message = d.Message + " (suppressed)"
		}
		out = append(out, d)
	}
	return out
}

// memoryDir resolves the directory holding memory.yaml.
//
// A configured path may name either the .vulnetix directory or the memory file
// inside it; both are what a user reaching for the setting would reasonably
// type, so both are accepted. A relative path is resolved against the
// workspace root rather than the server's working directory, which the user has
// no reason to know about.
func memoryDir(root, configured string) string {
	if configured == "" {
		return filepath.Join(root, vulnetixDirName)
	}
	path := configured
	if !filepath.IsAbs(path) {
		path = filepath.Join(root, path)
	}
	if filepath.Base(path) == memory.FileName {
		return filepath.Dir(path)
	}
	return path
}

// categoryOf maps a diagnostic source onto the suppression category the shared
// matcher uses.
func categoryOf(source string) string {
	switch source {
	case SourceSCA:
		return "sca"
	case "vulnetix-secrets":
		return "secrets"
	case "vulnetix-iac":
		return "iac"
	case "vulnetix-containers":
		return "oci"
	case "vulnetix-license":
		return "license"
	case "vulnetix-malware":
		return "malware"
	default:
		return "sast"
	}
}

// findingIDOf recovers the finding identity a rule may be anchored on.
func findingIDOf(d protocol.Diagnostic) string {
	data, ok := decodeDiagnosticData(d)
	if !ok {
		return ""
	}
	if data.SCA != nil && len(data.SCA.CveIDs) > 0 {
		// A dependency rule is anchored on the advisory, not on the synthesised
		// composite id: "ignore CVE-2021-23337" is what someone writes.
		return data.SCA.CveIDs[0]
	}
	return data.FindingID
}
