package lsp

import (
	"strings"
	"time"

	"github.com/vulnetix/cli/v3/internal/fix"
)

// Settings is the validated view of the editor's `vulnetix.*` configuration.
//
// Every field here has already been range-checked. That is the contract, not a
// convenience: the settings arrive from a user-editable JSON file over
// workspace/didChangeConfiguration, and a scanner that stops working because
// someone typed a negative number into settings.json is indistinguishable from
// a broken scanner. A value that cannot be used is logged and replaced with the
// default; it is never propagated and never disables analysis.
type Settings struct {
	// Debounce is the quiet period after a keystroke before analysis runs.
	Debounce time.Duration
	// MemoryLimitBytes caps the document content held in memory.
	MemoryLimitBytes int64
	// LowAsHint renders low and info findings as Hint rather than Information.
	// Set from diagnostics.mapLowTo.
	LowAsHint bool
	// MinimumSeverity hides findings below this level. Empty means show all.
	MinimumSeverity string
	// ShowSuppressed publishes suppressed findings as hints instead of dropping
	// them.
	ShowSuppressed bool
	// MemoryPath overrides the location of the .vulnetix directory holding
	// memory.yaml. Empty means the workspace default.
	MemoryPath string
	// Suppressions are editor-level ignore rules, which take precedence over the
	// memory file.
	Suppressions []SuppressionSetting
	// SCA configures dependency analysis.
	SCA scaSettings
}

// scaSettings is the dependency-analysis half of the configuration.
type scaSettings struct {
	Enabled bool
	// Strategy selects among the ranked Safe-Harbour versions.
	Strategy fix.Strategy
	// MaxMajorBump caps how many major versions a suggested fix may cross.
	MaxMajorBump int
	// AnnotateLockfiles publishes diagnostics in lockfiles as well as in the
	// manifests that declare a package.
	AnnotateLockfiles bool
}

// SuppressionSetting is one editor-level ignore rule.
type SuppressionSetting struct {
	RuleID    string
	FindingID string
	FilePath  string
	Reason    string
}

// Clamp bands. Chosen so every point inside them produces a server that still
// works; the ends are where behaviour stops being reasonable rather than where
// it stops being valid.
const (
	minDebounceMS = 0
	maxDebounceMS = 5000
	// A debounce of several seconds is a preference. Beyond that the editor
	// looks broken, so the value is capped rather than honoured.
	defaultDebounceMS = 400

	minMemoryLimitMB     = 128
	maxMemoryLimitMB     = 16384
	defaultMemoryLimitMB = 2048

	maxMajorBumpCeiling = 100
)

// DefaultSettings is what the server runs with before the client says anything,
// and what any individual invalid value falls back to.
func DefaultSettings() Settings {
	return Settings{
		Debounce:         defaultDebounceMS * time.Millisecond,
		MemoryLimitBytes: int64(defaultMemoryLimitMB) * 1024 * 1024,
		LowAsHint:        false,
		ShowSuppressed:   false,
		SCA:              defaultSCASettings(),
	}
}

func defaultSCASettings() scaSettings {
	return scaSettings{
		Enabled: true,
		// The editor defaults to the safest available version, where `vulnetix
		// fix` defaults to stable. Deliberate: a one-click fix in an editor is
		// applied with less deliberation than a command someone typed, so it
		// should prefer the lowest-risk target.
		Strategy:          fix.StrategySafest,
		MaxMajorBump:      0,
		AnnotateLockfiles: true,
	}
}

// ParseSettings converts the raw configuration object into validated settings.
//
// raw is the value of the `vulnetix` key from initializationOptions or from
// workspace/didChangeConfiguration. Anything missing, wrongly typed or out of
// range falls back to its default and is reported through logf.
func ParseSettings(raw map[string]any, logf func(string, ...any)) Settings {
	s := DefaultSettings()
	if raw == nil {
		return s
	}

	warn := func(format string, args ...any) {
		if logf != nil {
			logf(format, args...)
		}
	}

	if ms, ok := readInt(raw, "scan", "debounceMs"); ok {
		if ms < minDebounceMS || ms > maxDebounceMS {
			warn("settings: scan.debounceMs %d is outside %d..%d; using %d",
				ms, minDebounceMS, maxDebounceMS, defaultDebounceMS)
		} else {
			s.Debounce = time.Duration(ms) * time.Millisecond
		}
	}

	if mb, ok := readInt(raw, "lsp", "memoryLimitMb"); ok {
		if mb < minMemoryLimitMB || mb > maxMemoryLimitMB {
			warn("settings: lsp.memoryLimitMb %d is outside %d..%d; using %d",
				mb, minMemoryLimitMB, maxMemoryLimitMB, defaultMemoryLimitMB)
		} else {
			s.MemoryLimitBytes = int64(mb) * 1024 * 1024
		}
	}

	if v, ok := readString(raw, "diagnostics", "mapLowTo"); ok {
		switch strings.ToLower(v) {
		case "hint":
			s.LowAsHint = true
		case "information":
			s.LowAsHint = false
		default:
			warn("settings: diagnostics.mapLowTo %q is not information or hint; using information", v)
		}
	}
	if v, ok := readString(raw, "diagnostics", "minimumSeverity"); ok {
		if !isKnownSeverity(v) {
			warn("settings: diagnostics.minimumSeverity %q is not a severity; showing all findings", v)
		} else {
			s.MinimumSeverity = strings.ToLower(strings.TrimSpace(v))
		}
	}
	if v, ok := readBool(raw, "diagnostics", "showSuppressed"); ok {
		s.ShowSuppressed = v
	}
	if v, ok := readString(raw, "memory", "path"); ok {
		s.MemoryPath = v
	}

	if v, ok := readBool(raw, "sca", "enabled"); ok {
		s.SCA.Enabled = v
	}
	if v, ok := readBool(raw, "sca", "annotateLockfiles"); ok {
		s.SCA.AnnotateLockfiles = v
	}
	if v, ok := readString(raw, "sca", "safeHarbourStrategy"); ok {
		strategy, valid := parseStrategy(v)
		if !valid {
			warn("settings: sca.safeHarbourStrategy %q is not safest, latest or stable; using %q",
				v, defaultSCASettings().Strategy)
		} else {
			s.SCA.Strategy = strategy
		}
	}
	if v, ok := readInt(raw, "sca", "maxMajorBump"); ok {
		if v < 0 || v > maxMajorBumpCeiling {
			warn("settings: sca.maxMajorBump %d is outside 0..%d; using 0", v, maxMajorBumpCeiling)
		} else {
			s.SCA.MaxMajorBump = v
		}
	}

	s.Suppressions = parseSuppressions(raw)
	return s
}

// parseStrategy maps a configured string onto a fix strategy.
func parseStrategy(v string) (fix.Strategy, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "safest":
		return fix.StrategySafest, true
	case "latest":
		return fix.StrategyLatest, true
	case "stable":
		return fix.StrategyStable, true
	}
	return defaultSCASettings().Strategy, false
}

// parseSuppressions reads the editor-level ignore rules. A malformed entry is
// skipped rather than failing the whole list: one bad rule must not silence the
// scanner or discard the rules around it.
func parseSuppressions(raw map[string]any) []SuppressionSetting {
	list, ok := raw["suppressions"].([]any)
	if !ok {
		return nil
	}
	out := make([]SuppressionSetting, 0, len(list))
	for _, item := range list {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		rule := SuppressionSetting{
			RuleID:    stringField(obj, "ruleId"),
			FindingID: stringField(obj, "findingId"),
			FilePath:  stringField(obj, "path"),
			Reason:    stringField(obj, "reason"),
		}
		// A rule anchored on nothing would match every finding, which is a
		// silent global mute. Refuse it.
		if rule.RuleID == "" && rule.FindingID == "" && rule.FilePath == "" {
			continue
		}
		out = append(out, rule)
	}
	return out
}

// ── Raw access ───────────────────────────────────────────────────────────────
//
// The client may send settings nested (`{"sca": {"enabled": true}}`) or flat
// with dotted keys (`{"sca.enabled": true}`) depending on how the configuration
// was assembled. Both are read, so neither shape silently does nothing.

func readValue(raw map[string]any, section, key string) (any, bool) {
	if sub, ok := raw[section].(map[string]any); ok {
		if v, found := sub[key]; found {
			return v, true
		}
	}
	if v, found := raw[section+"."+key]; found {
		return v, true
	}
	return nil, false
}

func readInt(raw map[string]any, section, key string) (int, bool) {
	v, ok := readValue(raw, section, key)
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		// JSON numbers decode as float64. A fractional value is a typo, not a
		// setting; treating it as absent keeps the default.
		if n != float64(int(n)) {
			return 0, false
		}
		return int(n), true
	case int:
		return n, true
	case int64:
		return int(n), true
	}
	return 0, false
}

func readBool(raw map[string]any, section, key string) (bool, bool) {
	v, ok := readValue(raw, section, key)
	if !ok {
		return false, false
	}
	b, ok := v.(bool)
	return b, ok
}

func readString(raw map[string]any, section, key string) (string, bool) {
	v, ok := readValue(raw, section, key)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	return s, true
}

func stringField(obj map[string]any, key string) string {
	if s, ok := obj[key].(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

// isKnownSeverity guards the minimumSeverity setting.
//
// An unrecognised value shows everything rather than nothing. Getting this
// backwards would let a typo hide every finding in the workspace, which is the
// one failure mode a security tool must not have.
func isKnownSeverity(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "critical", "high", "medium", "low", "info":
		return true
	}
	return false
}
