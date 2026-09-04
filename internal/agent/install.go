package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// hookMatcher is the tool-name pattern the guard needs to see.
//
// Shell calls carry install commands; file writes carry manifest edits. Nothing
// else can add a dependency, and matching more would run the binary on every
// read the agent performs.
const hookMatcher = "Bash|Edit|Write|MultiEdit"

// hookRegistration is one event and the matcher it needs.
//
// The matcher is per-event, not global. A tool-name pattern is right for
// PreToolUse and meaningless for the session events, which carry no tool: giving
// SessionStart a matcher of "Bash|Edit|Write|MultiEdit" registers a hook that
// can never fire, which is worse than not registering it, because the
// configuration then claims a surface that does nothing.
type hookRegistration struct {
	event Event
	// matcher is empty for events that have nothing to match on, and the key is
	// then omitted from the written entry.
	matcher string
}

// hookEvents are the events the guard answers. Registering only these keeps a
// host from paying for a process on events that return Silent by construction.
var hookEvents = []hookRegistration{
	{event: EventPreToolUse, matcher: hookMatcher},
	{event: EventSessionStart},
	{event: EventUserPromptSubmit},
}

// InstallResult records what wiring one host actually changed.
type InstallResult struct {
	Host Host
	// Wired lists the surfaces configured.
	Wired []Surface
	// Changed is false when everything was already in place, which is the
	// common case on a re-run and is worth saying rather than reporting work
	// that did not happen.
	Changed bool
	// Notes carry anything the user should know, including surfaces this build
	// deliberately did not configure.
	Notes []string
	Err   error
}

// InstallOptions controls what an install writes.
type InstallOptions struct {
	// DryRun reports what would change without writing.
	DryRun bool
	// Hooks configures lifecycle hooks where the host supports them.
	Hooks bool
}

// InstallHooks wires one host's hook configuration.
//
// Existing configuration is preserved: the file is read, this CLI's entry is
// added or updated in place, and everything else is written back untouched. A
// tool that replaces a user's settings file to add one line is not one people
// run twice.
func InstallHooks(h Host, opts InstallOptions) InstallResult {
	res := InstallResult{Host: h}

	if h.HookDialect == DialectNone {
		res.Notes = append(res.Notes,
			fmt.Sprintf("hooks not configured: %s's hook contract has not been verified against this CLI", h.Name))
		return res
	}

	path := ExpandHome(h.HookConfig)
	existing, err := readJSONObject(path)
	if err != nil {
		res.Err = err
		return res
	}

	updated, changed, err := applyHookConfig(existing, h.HookDialect)
	if err != nil {
		res.Err = err
		return res
	}

	res.Changed = changed
	res.Wired = append(res.Wired, SurfaceHooks)

	if h.HookDialect == DialectCodex {
		// Codex 0.153 added a trust gate: a hook it has not been told to trust
		// is skipped, with no error and no output. Writing the configuration is
		// therefore not the same as the guard running, and saying nothing here
		// would leave someone believing they are guarded when they are not.
		res.Notes = append(res.Notes,
			"Codex asks you to trust a hook the first time it sees one. Approve it when "+
				"prompted, or the guard stays silent — Codex skips an untrusted hook without "+
				"reporting anything.")
	}

	if !changed || opts.DryRun {
		return res
	}

	if err := writeJSONObject(path, updated); err != nil {
		res.Err = err
		return res
	}
	return res
}

// applyHookConfig inserts this CLI's hook entry into a host's configuration,
// reporting whether anything changed.
func applyHookConfig(doc map[string]any, dialect HookDialect) (map[string]any, bool, error) {
	if doc == nil {
		doc = map[string]any{}
	}

	// Codex nests its events under a top-level "hooks" object and rejects a
	// document with the event at the root. Claude Code nests under "hooks" too,
	// inside settings.json alongside everything else.
	container := childObject(doc, "hooks")

	if dialect == DialectCodex {
		if _, ok := doc["description"]; !ok {
			doc["description"] = "Vulnetix dependency guard"
		}
	}

	changed := false
	for _, reg := range hookEvents {
		entries, _ := container[string(reg.event)].([]any)
		next, evChanged := upsertHookEntry(entries, dialect, reg.matcher)
		if evChanged {
			changed = true
		}
		container[string(reg.event)] = next
	}
	doc["hooks"] = container
	return doc, changed, nil
}

// upsertHookEntry adds or refreshes the Vulnetix matcher group, leaving every
// other group in place and in order.
func upsertHookEntry(entries []any, dialect HookDialect, matcher string) ([]any, bool) {
	command := HookCommand()

	if matcher != "" && dialect == DialectCodex {
		// Codex matches on a regex it applies to the tool name, and its shell
		// tool is not called Bash on every version. Matching everything and
		// deciding in the binary is both simpler and stable across versions;
		// the guard returns Silent for anything it has nothing to say about.
		matcher = "*"
	}

	entry := map[string]any{
		"hooks": []any{map[string]any{
			"type":    "command",
			"command": command,
			"timeout": 30,
		}},
	}
	// Omitted rather than empty for the session events. An empty matcher is not
	// the same as no matcher: hosts read it as a pattern that matches nothing.
	if matcher != "" {
		entry["matcher"] = matcher
	}

	for i, raw := range entries {
		group, ok := raw.(map[string]any)
		if !ok || !groupIsOurs(group) {
			continue
		}
		if sameHookGroup(group, entry) {
			return entries, false
		}
		entries[i] = entry
		return entries, true
	}
	return append(entries, entry), true
}

// groupIsOurs reports whether a matcher group is the one this CLI wrote.
//
// Identified by what the command ends with rather than by position or by the
// binary's path. Position moves as a user edits their file, and the path is
// wrong the moment somebody installs the CLI somewhere else or renames it —
// which would silently append a second copy of the entry on every upgrade. The
// subcommand is the invariant.
func groupIsOurs(group map[string]any) bool {
	hooks, _ := group["hooks"].([]any)
	for _, raw := range hooks {
		h, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		cmd, _ := h["command"].(string)
		if strings.HasSuffix(strings.TrimSpace(strings.Trim(cmd, `"`)), "agent hook") {
			return true
		}
	}
	return false
}

func sameHookGroup(a, b map[string]any) bool {
	aj, errA := json.Marshal(a)
	bj, errB := json.Marshal(b)
	return errA == nil && errB == nil && string(aj) == string(bj)
}

func childObject(parent map[string]any, key string) map[string]any {
	if existing, ok := parent[key].(map[string]any); ok {
		return existing
	}
	child := map[string]any{}
	parent[key] = child
	return child
}

// readJSONObject reads a JSON object, treating a missing file as empty.
//
// A file that exists but does not parse is an error rather than something to
// overwrite: replacing a settings file somebody is mid-edit on would lose their
// work to fix a problem they did not have.
func readJSONObject(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]any{}, nil
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return map[string]any{}, nil
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON, leaving it alone: %w", path, err)
	}
	return doc, nil
}

func writeJSONObject(path string, doc map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding %s: %w", path, err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// Uninstall removes this CLI's hook entry, leaving the rest of the file as it
// was.
func Uninstall(h Host, opts InstallOptions) InstallResult {
	res := InstallResult{Host: h}
	if h.HookDialect == DialectNone {
		return res
	}

	path := ExpandHome(h.HookConfig)
	doc, err := readJSONObject(path)
	if err != nil {
		res.Err = err
		return res
	}

	container, ok := doc["hooks"].(map[string]any)
	if !ok {
		return res
	}

	for _, reg := range hookEvents {
		entries, _ := container[string(reg.event)].([]any)
		kept := make([]any, 0, len(entries))
		for _, raw := range entries {
			group, ok := raw.(map[string]any)
			if ok && groupIsOurs(group) {
				res.Changed = true
				continue
			}
			kept = append(kept, raw)
		}
		if len(kept) == 0 {
			delete(container, string(reg.event))
		} else {
			container[string(reg.event)] = kept
		}
	}

	if !res.Changed || opts.DryRun {
		return res
	}
	if err := writeJSONObject(path, doc); err != nil {
		res.Err = err
	}
	return res
}

// SortedHostIDs lists every known host identifier, for help text and docs.
func SortedHostIDs() []string {
	out := make([]string, 0, len(Hosts))
	for _, h := range Hosts {
		out = append(out, h.ID)
	}
	sort.Strings(out)
	return out
}
