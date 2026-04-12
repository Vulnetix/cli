package depsdev

import (
	"testing"
)

func TestEcosystemToSystem(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"npm", "NPM"},
		{"NPM", "NPM"},
		{"golang", "GO"},
		{"go", "GO"},
		{"Go", "GO"},
		{"pypi", "PYPI"},
		{"cargo", "CARGO"},
		{"maven", "MAVEN"},
		{"nuget", "NUGET"},
		{"rubygems", ""},
		{"", ""},
		{"unknown", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := EcosystemToSystem(tt.input)
			if got != tt.want {
				t.Errorf("EcosystemToSystem(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestEnrichmentMap(t *testing.T) {
	enrichments := []PackageEnrichment{
		{PackageRef: PackageRef{Name: "foo", Version: "1.0.0", Ecosystem: "npm"}},
		{PackageRef: PackageRef{Name: "bar", Version: "2.0.0", Ecosystem: "pypi"}},
	}

	m := EnrichmentMap(enrichments)

	if len(m) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(m))
	}

	if e, ok := m["foo@1.0.0"]; !ok {
		t.Error("expected foo@1.0.0 in map")
	} else if e.Ecosystem != "npm" {
		t.Errorf("expected ecosystem npm, got %s", e.Ecosystem)
	}

	if _, ok := m["bar@2.0.0"]; !ok {
		t.Error("expected bar@2.0.0 in map")
	}

	if _, ok := m["baz@1.0.0"]; ok {
		t.Error("unexpected baz@1.0.0 in map")
	}
}

func TestFindLatestVersion(t *testing.T) {
	tests := []struct {
		name     string
		pkg      *PackageResponse
		wantVer  string
	}{
		{
			name: "default version exists",
			pkg: &PackageResponse{
				Versions: []VersionSummary{
					{VersionKey: VersionKey{Version: "1.0.0"}},
					{VersionKey: VersionKey{Version: "2.0.0"}, IsDefault: true},
					{VersionKey: VersionKey{Version: "3.0.0-beta"}},
				},
			},
			wantVer: "2.0.0",
		},
		{
			name: "no default falls back to last",
			pkg: &PackageResponse{
				Versions: []VersionSummary{
					{VersionKey: VersionKey{Version: "1.0.0"}},
					{VersionKey: VersionKey{Version: "2.0.0"}},
				},
			},
			wantVer: "2.0.0",
		},
		{
			name:    "empty versions",
			pkg:     &PackageResponse{},
			wantVer: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findLatestVersion(tt.pkg)
			if got != tt.wantVer {
				t.Errorf("findLatestVersion() = %q, want %q", got, tt.wantVer)
			}
		})
	}
}

func TestCountVersionsBehind(t *testing.T) {
	pkg := &PackageResponse{
		Versions: []VersionSummary{
			{VersionKey: VersionKey{Version: "1.0.0"}},
			{VersionKey: VersionKey{Version: "1.1.0"}},
			{VersionKey: VersionKey{Version: "1.2.0"}},
			{VersionKey: VersionKey{Version: "2.0.0"}},
		},
	}

	tests := []struct {
		installed string
		want      int
	}{
		{"1.0.0", 3},
		{"1.1.0", 2},
		{"1.2.0", 1},
		{"2.0.0", 0},
		{"0.9.0", 0}, // not found in list
	}

	for _, tt := range tests {
		t.Run(tt.installed, func(t *testing.T) {
			got := countVersionsBehind(tt.installed, pkg)
			if got != tt.want {
				t.Errorf("countVersionsBehind(%q) = %d, want %d", tt.installed, got, tt.want)
			}
		})
	}
}
