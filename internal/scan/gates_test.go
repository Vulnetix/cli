package scan

import (
	"testing"
)

// ── IsVersionSpecPinned ──────────────────────────────────────────────────────

func TestIsVersionSpecPinned(t *testing.T) {
	tests := []struct {
		spec   string
		pinned bool
	}{
		// Pinned — exact version or lock-file entry.
		{"", true},
		{"1.0.0", true},
		{"1.2.3", true},
		{"v1.0.0", true},
		{"0.0.1", true},
		{"2.10.0", true},

		// Unpinned — range operators.
		{"^1.0.0", false},
		{"~1.0.0", false},
		{">=1.0.0", false},
		{"<=1.0.0", false},
		{"!=1.0.0", false},
		{">1.0.0", false},
		{"<1.0.0", false},
		{"~=1.0.0", false},

		// Unpinned — wildcard / symbolic.
		{"*", false},
		{"latest", false},
		{"x", false},

		// Leading/trailing whitespace is stripped.
		{"  1.2.3  ", true},
		{"  ^1.0.0  ", false},
	}
	for _, tt := range tests {
		got := IsVersionSpecPinned(tt.spec)
		if got != tt.pinned {
			t.Errorf("IsVersionSpecPinned(%q) = %v, want %v", tt.spec, got, tt.pinned)
		}
	}
}

// ── ExploitMeetsThreshold ────────────────────────────────────────────────────

// makeEV is a test helper that constructs a minimal EnrichedVuln.
func makeEV(exploitCount int, hasWeaponized, inCisa, inVulnCheck, inEu bool) EnrichedVuln {
	ev := EnrichedVuln{}
	ev.InCisaKev = inCisa
	ev.InVulnCheckKev = inVulnCheck
	ev.InEuKev = inEu
	if exploitCount > 0 || hasWeaponized {
		ev.ExploitIntel = &ExploitSummary{
			ExploitCount:  exploitCount,
			HasWeaponized: hasWeaponized,
		}
	}
	return ev
}

func TestExploitMeetsThreshold(t *testing.T) {
	tests := []struct {
		name      string
		ev        EnrichedVuln
		threshold string
		want      bool
	}{
		// ── poc tier ────────────────────────────────────────────────────────────
		{"poc: ExploitCount>0", makeEV(1, false, false, false, false), "poc", true},
		{"poc: InCisaKev", makeEV(0, false, true, false, false), "poc", true},
		{"poc: InVulnCheckKev", makeEV(0, false, false, true, false), "poc", true},
		{"poc: InEuKev", makeEV(0, false, false, false, true), "poc", true},
		{"poc: none set", makeEV(0, false, false, false, false), "poc", false},

		// ── active tier ─────────────────────────────────────────────────────────
		{"active: InCisaKev", makeEV(0, false, true, false, false), "active", true},
		{"active: InVulnCheckKev", makeEV(0, false, false, true, false), "active", true},
		{"active: InEuKev", makeEV(0, false, false, false, true), "active", true},
		{"active: HasWeaponized", makeEV(0, true, false, false, false), "active", true},
		// ExploitCount alone does NOT satisfy active.
		{"active: ExploitCount only", makeEV(5, false, false, false, false), "active", false},
		{"active: none set", makeEV(0, false, false, false, false), "active", false},

		// ── weaponized tier ─────────────────────────────────────────────────────
		{"weaponized: HasWeaponized", makeEV(0, true, false, false, false), "weaponized", true},
		// KEV or ExploitCount alone does NOT satisfy weaponized.
		{"weaponized: InCisaKev only", makeEV(0, false, true, false, false), "weaponized", false},
		{"weaponized: InEuKev only", makeEV(0, false, false, false, true), "weaponized", false},
		{"weaponized: ExploitCount only", makeEV(3, false, false, false, false), "weaponized", false},
		{"weaponized: none set", makeEV(0, false, false, false, false), "weaponized", false},

		// ── unknown threshold always false ──────────────────────────────────────
		{"unknown threshold", makeEV(100, true, true, true, true), "critical", false},
	}
	for _, tt := range tests {
		got := ExploitMeetsThreshold(tt.ev, tt.threshold)
		if got != tt.want {
			t.Errorf("[%s] ExploitMeetsThreshold(%q) = %v, want %v", tt.name, tt.threshold, got, tt.want)
		}
	}
}

// ── HasAnyKev ────────────────────────────────────────────────────────────────

func TestHasAnyKev(t *testing.T) {
	tests := []struct {
		name string
		ev   EnrichedVuln
		want bool
	}{
		{"all false", makeEV(0, false, false, false, false), false},
		{"InCisaKev only", makeEV(0, false, true, false, false), true},
		{"InVulnCheckKev only", makeEV(0, false, false, true, false), true},
		{"InEuKev only", makeEV(0, false, false, false, true), true},
		{"all KEV catalogs", makeEV(0, false, true, true, true), true},
	}
	for _, tt := range tests {
		got := HasAnyKev(tt.ev)
		if got != tt.want {
			t.Errorf("[%s] HasAnyKev() = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// ── NormaliseReleaseForEOL ───────────────────────────────────────────────────

func TestNormaliseReleaseForEOL(t *testing.T) {
	tests := []struct {
		product string
		version string
		want    string
	}{
		// go: major.minor
		{"go", "1.21.3", "1.21"},
		{"go", "1.21", "1.21"},
		{"go", "v1.22.0", "1.22"},

		// nodejs: major only
		{"nodejs", "18.20.4", "18"},
		{"nodejs", "18", "18"},
		{"nodejs", "v20.1.0", "20"},

		// python: major.minor
		{"python", "3.10.4", "3.10"},
		{"python", "3.10", "3.10"},
		{"python", "v3.12.0", "3.12"},

		// ruby: major.minor
		{"ruby", "3.2.1", "3.2"},
		{"ruby", "3.2", "3.2"},

		// Unknown product defaults to major.minor (same as go/python/ruby).
		{"dart", "2.18.3", "2.18"},
		{"dart", "2", "2"},

		// Unparseable: empty string.
		{"go", "", ""},
		{"nodejs", "v", ""},
	}
	for _, tt := range tests {
		got := NormaliseReleaseForEOL(tt.product, tt.version)
		if got != tt.want {
			t.Errorf("NormaliseReleaseForEOL(%q, %q) = %q, want %q", tt.product, tt.version, got, tt.want)
		}
	}
}
