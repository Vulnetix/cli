package lsp

import (
	"testing"
	"time"

	"github.com/vulnetix/cli/v3/internal/fix"
)

// The settings file is user-editable, so every value here is something someone
// can actually type. None may switch analysis off, and none may reach the rest
// of the server unclamped.
func TestParseSettingsRejectsBadValuesAndKeepsWorking(t *testing.T) {
	defaults := DefaultSettings()

	cases := []struct {
		name string
		raw  map[string]any
	}{
		{"negative debounce", map[string]any{"scan": map[string]any{"debounceMs": float64(-1)}}},
		{"absurd debounce", map[string]any{"scan": map[string]any{"debounceMs": float64(1 << 20)}}},
		{"zero memory limit", map[string]any{"lsp": map[string]any{"memoryLimitMb": float64(0)}}},
		{"negative memory limit", map[string]any{"lsp": map[string]any{"memoryLimitMb": float64(-4096)}}},
		{"nonsense strategy", map[string]any{"sca": map[string]any{"safeHarbourStrategy": "nonsense"}}},
		{"negative major bump", map[string]any{"sca": map[string]any{"maxMajorBump": float64(-5)}}},
		{"wrong type for debounce", map[string]any{"scan": map[string]any{"debounceMs": "soon"}}},
		{"wrong type for strategy", map[string]any{"sca": map[string]any{"safeHarbourStrategy": float64(3)}}},
		{"wrong type for enabled", map[string]any{"sca": map[string]any{"enabled": "yes"}}},
		{"fractional debounce", map[string]any{"scan": map[string]any{"debounceMs": 12.5}}},
		{"nonsense mapLowTo", map[string]any{"diagnostics": map[string]any{"mapLowTo": "loud"}}},
		{"nonsense severity floor", map[string]any{"diagnostics": map[string]any{"minimumSeverity": "spicy"}}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseSettings(tc.raw, nil)

			if got.Debounce != defaults.Debounce {
				t.Errorf("Debounce = %v, want the default %v", got.Debounce, defaults.Debounce)
			}
			if got.MemoryLimitBytes != defaults.MemoryLimitBytes {
				t.Errorf("MemoryLimitBytes = %d, want the default %d", got.MemoryLimitBytes, defaults.MemoryLimitBytes)
			}
			if got.SCA.Strategy != defaults.SCA.Strategy {
				t.Errorf("Strategy = %q, want the default %q", got.SCA.Strategy, defaults.SCA.Strategy)
			}
			if got.SCA.MaxMajorBump != defaults.SCA.MaxMajorBump {
				t.Errorf("MaxMajorBump = %d, want the default %d", got.SCA.MaxMajorBump, defaults.SCA.MaxMajorBump)
			}
			// The two load-bearing assertions: whatever was typed, analysis is
			// still on and nothing is being hidden.
			if !got.SCA.Enabled {
				t.Error("SCA.Enabled = false; a bad value must never disable analysis")
			}
			if got.MinimumSeverity != "" {
				t.Errorf("MinimumSeverity = %q; a bad value must not hide findings", got.MinimumSeverity)
			}
		})
	}
}

func TestParseSettingsAcceptsValidValues(t *testing.T) {
	got := ParseSettings(map[string]any{
		"scan": map[string]any{"debounceMs": float64(150)},
		"lsp":  map[string]any{"memoryLimitMb": float64(512)},
		"sca": map[string]any{
			"safeHarbourStrategy": "latest",
			"maxMajorBump":        float64(2),
			"annotateLockfiles":   false,
		},
		"diagnostics": map[string]any{
			"mapLowTo":        "hint",
			"showSuppressed":  true,
			"minimumSeverity": "high",
		},
		"memory": map[string]any{"path": ".config/vulnetix"},
	}, nil)

	if got.Debounce != 150*time.Millisecond {
		t.Errorf("Debounce = %v, want 150ms", got.Debounce)
	}
	if got.MemoryLimitBytes != 512*1024*1024 {
		t.Errorf("MemoryLimitBytes = %d, want 512MiB", got.MemoryLimitBytes)
	}
	if got.SCA.Strategy != fix.StrategyLatest {
		t.Errorf("Strategy = %q, want latest", got.SCA.Strategy)
	}
	if got.SCA.MaxMajorBump != 2 {
		t.Errorf("MaxMajorBump = %d, want 2", got.SCA.MaxMajorBump)
	}
	if got.SCA.AnnotateLockfiles {
		t.Error("AnnotateLockfiles = true, want false")
	}
	if !got.LowAsHint || !got.ShowSuppressed {
		t.Error("diagnostics flags were not applied")
	}
	if got.MinimumSeverity != "high" {
		t.Errorf("MinimumSeverity = %q, want high", got.MinimumSeverity)
	}
	if got.MemoryPath != ".config/vulnetix" {
		t.Errorf("MemoryPath = %q", got.MemoryPath)
	}
}

// The editor may send settings nested or flattened depending on how the
// configuration was assembled. Neither shape may silently do nothing.
func TestParseSettingsAcceptsDottedKeys(t *testing.T) {
	got := ParseSettings(map[string]any{
		"sca.safeHarbourStrategy": "stable",
		"scan.debounceMs":         float64(250),
	}, nil)

	if got.SCA.Strategy != fix.StrategyStable {
		t.Errorf("Strategy = %q, want stable", got.SCA.Strategy)
	}
	if got.Debounce != 250*time.Millisecond {
		t.Errorf("Debounce = %v, want 250ms", got.Debounce)
	}
}

// The editor default is deliberately not the CLI default. Pin it so the
// divergence stays a decision rather than becoming a drift.
func TestDefaultStrategyIsSafest(t *testing.T) {
	if got := DefaultSettings().SCA.Strategy; got != fix.StrategySafest {
		t.Errorf("default strategy = %q, want safest", got)
	}
}

// A suppression rule anchored on nothing matches every finding, which would
// silence the scanner without saying so.
func TestParseSuppressionsRejectsUnanchoredRules(t *testing.T) {
	got := ParseSettings(map[string]any{
		"suppressions": []any{
			map[string]any{"reason": "we accept this"},
			map[string]any{"ruleId": "VNX-JS-001", "reason": "false positive"},
			"not an object",
		},
	}, nil)

	if len(got.Suppressions) != 1 {
		t.Fatalf("got %d rules, want 1 (the anchored one)", len(got.Suppressions))
	}
	if got.Suppressions[0].RuleID != "VNX-JS-001" {
		t.Errorf("RuleID = %q", got.Suppressions[0].RuleID)
	}
}

func TestParseSettingsNilIsDefaults(t *testing.T) {
	got := ParseSettings(nil, nil)
	want := DefaultSettings()

	if got.Debounce != want.Debounce || got.MemoryLimitBytes != want.MemoryLimitBytes || got.SCA != want.SCA {
		t.Errorf("nil settings should be the defaults, got %+v", got)
	}
	if len(got.Suppressions) != 0 {
		t.Errorf("nil settings should carry no suppressions, got %d", len(got.Suppressions))
	}
}

func TestVulnetixSectionUnwrapsEnvelope(t *testing.T) {
	inner := map[string]any{"sca": map[string]any{"enabled": false}}
	if got := vulnetixSection(map[string]any{"vulnetix": inner}); len(got) != 1 {
		t.Errorf("envelope not unwrapped: %v", got)
	}
	if got := vulnetixSection(inner); len(got) != 1 {
		t.Errorf("bare section should pass through: %v", got)
	}
}
