package versions

// MIRRORED — this test file is kept byte-identical between
// vdb-api/internal/versions and cli/internal/versions. Update both copies
// together.

import "testing"

func ptr(s string) *string { return &s }

func TestEvaluateStatusPrecedence(t *testing.T) {
	cases := []struct {
		name          string
		installed     string
		entries       []VersionEntry
		defaultStatus string
		opt           Options
		want          Status
		wantKind      string
	}{
		{
			name:      "exact unaffected beats affected range",
			installed: "1.5.0",
			entries: []VersionEntry{
				{Version: "0", Status: StatusAffected, LessThan: ptr("2.0.0")},
				{Version: "1.5.0", Status: StatusUnaffected},
			},
			want:     StatusUnaffected,
			wantKind: "exact-unaffected",
		},
		{
			name:      "exact unaffected with v prefix beats affected range",
			installed: "v1.5.0",
			entries: []VersionEntry{
				{Version: "0", Status: StatusAffected, LessThan: ptr("2.0.0")},
				{Version: "1.5.0", Status: StatusUnaffected},
			},
			want:     StatusUnaffected,
			wantKind: "exact-unaffected",
		},
		{
			name:      "exact affected match",
			installed: "1.14.1",
			entries: []VersionEntry{
				{Version: "1.14.1", Status: StatusAffected},
				{Version: "0.30.4", Status: StatusAffected},
			},
			want:     StatusAffected,
			wantKind: "exact-affected",
		},
		{
			name:      "exact list miss falls to default unaffected",
			installed: "0.30.5",
			entries: []VersionEntry{
				{Version: "1.14.1", Status: StatusAffected},
				{Version: "0.30.4", Status: StatusAffected},
			},
			defaultStatus: "unaffected",
			want:          StatusUnaffected,
			wantKind:      "default",
		},
		{
			name:      "affected range with introduced lower bound excludes below",
			installed: "0.9.0",
			entries: []VersionEntry{
				{Version: "1.0.0", Status: StatusAffected, LessThan: ptr("2.0.0")},
			},
			want:     StatusUnknown,
			wantKind: "none",
		},
		{
			name:      "affected range with introduced lower bound includes inside",
			installed: "1.5.0",
			entries: []VersionEntry{
				{Version: "1.0.0", Status: StatusAffected, LessThan: ptr("2.0.0")},
			},
			want:     StatusAffected,
			wantKind: "range-affected",
		},
		{
			name:      "lessThan upper bound is exclusive",
			installed: "2.0.0",
			entries: []VersionEntry{
				{Version: "1.0.0", Status: StatusAffected, LessThan: ptr("2.0.0")},
			},
			want: StatusUnknown,
		},
		{
			name:      "lessThanOrEqual upper bound is inclusive",
			installed: "2.0.0",
			entries: []VersionEntry{
				{Version: "1.0.0", Status: StatusAffected, LessThanOrEqual: ptr("2.0.0")},
			},
			want: StatusAffected,
		},
		{
			name:      "unaffected range beats affected range",
			installed: "1.5.0",
			entries: []VersionEntry{
				{Version: "0", Status: StatusAffected, LessThan: ptr("2.0.0")},
				{Version: "1.4.0", Status: StatusUnaffected, LessThan: ptr("1.6.0")},
			},
			want:     StatusUnaffected,
			wantKind: "range-unaffected",
		},
		{
			name:      "default affected when nothing matches",
			installed: "5.0.0",
			entries: []VersionEntry{
				{Version: "1.0.0", Status: StatusAffected, LessThan: ptr("2.0.0")},
			},
			defaultStatus: "affected",
			want:          StatusAffected,
			wantKind:      "default",
		},
		{
			name:          "unknown when no entries and no default",
			installed:     "1.0.0",
			entries:       nil,
			defaultStatus: "",
			want:          StatusUnknown,
			wantKind:      "none",
		},
		{
			name:      "unparseable installed version is unknown",
			installed: "not-a-version!",
			entries: []VersionEntry{
				{Version: "1.0.0", Status: StatusAffected},
			},
			want:     StatusUnknown,
			wantKind: "unparseable-version",
		},
		{
			name:      "junk entries skipped, good entry still wins",
			installed: "1.5.0",
			entries: []VersionEntry{
				{Version: "unspecified", Status: StatusAffected},
				{Version: "1.5.0", Status: StatusUnaffected},
			},
			want:     StatusUnaffected,
			wantKind: "exact-unaffected",
		},
		{
			name:      "wildcard affected entry matches everything",
			installed: "42.0.0",
			entries: []VersionEntry{
				{Version: "*", Status: StatusAffected},
			},
			want:     StatusAffected,
			wantKind: "range-affected",
		},
		{
			name:      "wildcard affected loses to exact unaffected",
			installed: "1.5.0",
			entries: []VersionEntry{
				{Version: "*", Status: StatusAffected},
				{Version: "1.5.0", Status: StatusUnaffected},
			},
			want:     StatusUnaffected,
			wantKind: "exact-unaffected",
		},
		{
			name:      "wildcard lessThan means unbounded upper",
			installed: "99.0.0",
			entries: []VersionEntry{
				{Version: "1.0.0", Status: StatusAffected, LessThan: ptr("*")},
			},
			want:     StatusAffected,
			wantKind: "range-affected",
		},
		{
			name:      "pseudo-version installed, unaffected exact base, npm policy",
			installed: "5.3.2-0.20260526213025-e8e5b83ca9a5",
			entries: []VersionEntry{
				{Version: "0", Status: StatusAffected, LessThan: ptr("6.0.0")},
				{Version: "5.3.2", Status: StatusUnaffected},
			},
			opt:      Options{Ecosystem: "npm"},
			want:     StatusUnaffected,
			wantKind: "exact-unaffected",
		},
		{
			name:      "pseudo-version installed, unaffected exact base, go policy stays in range",
			installed: "5.3.2-0.20260526213025-e8e5b83ca9a5",
			entries: []VersionEntry{
				{Version: "0", Status: StatusAffected, LessThan: ptr("6.0.0")},
				{Version: "5.3.2", Status: StatusUnaffected},
			},
			opt:      Options{Ecosystem: "go"},
			want:     StatusAffected,
			wantKind: "range-affected",
		},
		{
			name:      "go pseudo-version inside zero-lower affected range",
			installed: "0.0.0-20220622213112-05595931fe9d",
			entries: []VersionEntry{
				{Version: "0", Status: StatusAffected, LessThan: ptr("0.5.0")},
			},
			opt:      Options{Ecosystem: "go"},
			want:     StatusAffected,
			wantKind: "range-affected",
		},
		{
			name:      "prerelease included in affected range",
			installed: "9.3.0-beta",
			entries: []VersionEntry{
				{Version: "0", Status: StatusAffected, LessThan: ptr("9.3.0")},
			},
			want:     StatusAffected,
			wantKind: "range-affected",
		},
		{
			name:      "prerelease does not exact-match base release",
			installed: "9.3.0-beta",
			entries: []VersionEntry{
				{Version: "9.3.0", Status: StatusUnaffected},
			},
			defaultStatus: "affected",
			want:          StatusAffected,
			wantKind:      "default",
		},
		{
			name:      "changes step-down to unaffected within range",
			installed: "1.8.0",
			entries: []VersionEntry{
				{
					Version: "1.0.0", Status: StatusAffected, LessThan: ptr("2.0.0"),
					Changes: []VersionChange{{At: "1.7.0", Status: StatusUnaffected}},
				},
			},
			want:     StatusUnaffected,
			wantKind: "range-unaffected",
		},
		{
			name:      "changes below installed threshold do not apply",
			installed: "1.5.0",
			entries: []VersionEntry{
				{
					Version: "1.0.0", Status: StatusAffected, LessThan: ptr("2.0.0"),
					Changes: []VersionChange{{At: "1.7.0", Status: StatusUnaffected}},
				},
			},
			want:     StatusAffected,
			wantKind: "range-affected",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ev := EvaluateStatus(c.installed, c.entries, c.defaultStatus, c.opt)
			if got != c.want {
				t.Errorf("EvaluateStatus = %v (kind %q), want %v", got, ev.MatchKind, c.want)
			}
			if c.wantKind != "" && ev.MatchKind != c.wantKind {
				t.Errorf("MatchKind = %q, want %q", ev.MatchKind, c.wantKind)
			}
		})
	}
}

func TestBuildRangeStrings(t *testing.T) {
	t.Run("introduced bound included", func(t *testing.T) {
		vr, uv := BuildRangeStrings([]VersionEntry{
			{Version: "1.0.0", Status: StatusAffected, LessThan: ptr("2.0.0")},
		}, "")
		if vr != ">= 1.0.0 < 2.0.0" {
			t.Errorf("versionRange = %q", vr)
		}
		if uv != "" {
			t.Errorf("unaffectedVersions = %q", uv)
		}
	})
	t.Run("zero lower bound omitted", func(t *testing.T) {
		vr, _ := BuildRangeStrings([]VersionEntry{
			{Version: "0", Status: StatusAffected, LessThan: ptr("2.11.2")},
		}, "")
		if vr != "< 2.11.2" {
			t.Errorf("versionRange = %q", vr)
		}
	})
	t.Run("exact and ranges OR-joined plus unaffected", func(t *testing.T) {
		vr, uv := BuildRangeStrings([]VersionEntry{
			{Version: "0", Status: StatusAffected, LessThan: ptr("2.11.2")},
			{Version: "1.14.1", Status: StatusAffected},
			{Version: "1.5.0", Status: StatusUnaffected},
		}, "")
		if vr != "< 2.11.2 || = 1.14.1" {
			t.Errorf("versionRange = %q", vr)
		}
		if uv != "= 1.5.0" {
			t.Errorf("unaffectedVersions = %q", uv)
		}
	})
	t.Run("lessThanOrEqual renders inclusive", func(t *testing.T) {
		vr, _ := BuildRangeStrings([]VersionEntry{
			{Version: "0", Status: StatusAffected, LessThanOrEqual: ptr("1.5.0")},
		}, "")
		if vr != "<= 1.5.0" {
			t.Errorf("versionRange = %q", vr)
		}
	})
	t.Run("default affected with no entries renders wildcard", func(t *testing.T) {
		vr, _ := BuildRangeStrings(nil, "affected")
		if vr != "*" {
			t.Errorf("versionRange = %q", vr)
		}
	})
	t.Run("junk entries skipped", func(t *testing.T) {
		vr, _ := BuildRangeStrings([]VersionEntry{
			{Version: "unspecified", Status: StatusAffected},
			{Version: "1.0.0", Status: StatusAffected},
		}, "")
		if vr != "= 1.0.0" {
			t.Errorf("versionRange = %q", vr)
		}
	})
	t.Run("wildcard entry renders star", func(t *testing.T) {
		vr, _ := BuildRangeStrings([]VersionEntry{
			{Version: "*", Status: StatusAffected},
		}, "")
		if vr != "*" {
			t.Errorf("versionRange = %q", vr)
		}
	})
	t.Run("round-trip: emitted strings parse and agree with evaluator", func(t *testing.T) {
		entries := []VersionEntry{
			{Version: "1.0.0", Status: StatusAffected, LessThan: ptr("2.0.0")},
			{Version: "3.1.4", Status: StatusAffected},
		}
		vr, _ := BuildRangeStrings(entries, "")
		rs, err := ParseRange(vr)
		if err != nil {
			t.Fatalf("ParseRange(%q): %v", vr, err)
		}
		for _, probe := range []struct {
			version string
			want    bool
		}{
			{"1.5.0", true}, {"3.1.4", true}, {"0.9.0", false}, {"2.0.0", false}, {"3.1.5", false},
		} {
			v, _ := Parse(probe.version)
			if got := rs.Contains(v, PseudoBaseEqual); got != probe.want {
				t.Errorf("round-trip Contains(%q in %q) = %v, want %v", probe.version, vr, got, probe.want)
			}
		}
	})
}

func TestBuildRangeList(t *testing.T) {
	list := BuildRangeList([]VersionEntry{
		{Version: "0", Status: StatusAffected, LessThan: ptr("2.11.2")},
		{Version: "1.14.1", Status: StatusAffected},
		{Version: "1.5.0", Status: StatusUnaffected},
	}, "")
	if len(list) != 2 || list[0] != "< 2.11.2" || list[1] != "= 1.14.1" {
		t.Errorf("BuildRangeList = %v", list)
	}
	if got := BuildRangeList(nil, "affected"); len(got) != 1 || got[0] != "*" {
		t.Errorf("BuildRangeList default = %v", got)
	}
}

func TestDeriveFixedVersions(t *testing.T) {
	// Values pass through verbatim (matching the historical handler loops):
	// non-SemVer fix identifiers like git shas, "1.0.2k", and "1:2.4.5-1"
	// are legitimate in some ecosystems and must not be dropped.
	got := DeriveFixedVersions([]VersionEntry{
		{Version: "0", Status: StatusAffected, LessThan: ptr("2.0.0")},
		{Version: "1.9.0", Status: StatusAffected, LessThanOrEqual: ptr("1.9.9")},
		{Version: "3.0.1", Status: StatusUnaffected},
		{Version: "0", Status: StatusAffected, LessThan: ptr("2.0.0")},            // duplicate
		{Version: "1.0.2k", Status: StatusUnaffected},                             // letter version preserved
		{Version: "0", Status: StatusAffected, LessThan: ptr("aabbccddeeff0011")}, // git sha preserved
	})
	want := []string{"2.0.0", "1.9.9", "3.0.1", "1.0.2k", "aabbccddeeff0011"}
	if len(got) != len(want) {
		t.Fatalf("DeriveFixedVersions = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("DeriveFixedVersions[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestNormalizeStatus(t *testing.T) {
	cases := []struct {
		in   string
		want Status
	}{
		{"affected", StatusAffected},
		{"AFFECTED", StatusAffected},
		{"known_affected", StatusAffected},
		{"vulnerable", StatusAffected},
		{"unaffected", StatusUnaffected},
		{"known_not_affected", StatusUnaffected},
		{"not_affected", StatusUnaffected},
		{"unknown", StatusUnknown},
		{"", StatusUnknown},
		{"garbage", StatusUnknown},
	}
	for _, c := range cases {
		if got := NormalizeStatus(c.in); got != c.want {
			t.Errorf("NormalizeStatus(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
