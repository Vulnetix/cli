package purl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantErr   bool
		wantType  string
		wantNS    string
		wantName  string
		wantVer   string
		wantQuals map[string]string
		wantSub   string
	}{
		{
			name:     "simple npm",
			input:    "pkg:npm/express",
			wantType: "npm",
			wantName: "express",
		},
		{
			name:     "scoped npm with version",
			input:    "pkg:npm/@babel/core@7.0.0",
			wantType: "npm",
			wantNS:   "@babel",
			wantName: "core",
			wantVer:  "7.0.0",
		},
		{
			name:     "maven with namespace and version",
			input:    "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
			wantType: "maven",
			wantNS:   "org.apache.commons",
			wantName: "commons-lang3",
			wantVer:  "3.12.0",
		},
		{
			name:     "pypi with version",
			input:    "pkg:pypi/requests@2.28.0",
			wantType: "pypi",
			wantName: "requests",
			wantVer:  "2.28.0",
		},
		{
			name:     "golang with deep namespace",
			input:    "pkg:golang/github.com/go-chi/chi/v5@5.0.8",
			wantType: "golang",
			wantNS:   "github.com/go-chi/chi",
			wantName: "v5",
			wantVer:  "5.0.8",
		},
		{
			name:     "cargo with version",
			input:    "pkg:cargo/serde@1.0.0",
			wantType: "cargo",
			wantName: "serde",
			wantVer:  "1.0.0",
		},
		{
			name:      "with qualifiers and subpath",
			input:     "pkg:npm/express@4.17.1?repository_url=https://registry.npmjs.org#src",
			wantType:  "npm",
			wantName:  "express",
			wantVer:   "4.17.1",
			wantQuals: map[string]string{"repository_url": "https://registry.npmjs.org"},
			wantSub:   "src",
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "no scheme",
			input:   "npm/express",
			wantErr: true,
		},
		{
			name:    "no type - just scheme",
			input:   "pkg:/express",
			wantErr: true,
		},
		{
			name:    "no name",
			input:   "pkg:npm/",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := Parse(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.wantType, p.Type)
			assert.Equal(t, tt.wantNS, p.Namespace)
			assert.Equal(t, tt.wantName, p.Name)
			assert.Equal(t, tt.wantVer, p.Version)
			if tt.wantQuals != nil {
				assert.Equal(t, tt.wantQuals, p.Qualifiers)
			}
			if tt.wantSub != "" {
				assert.Equal(t, tt.wantSub, p.Subpath)
			}
		})
	}
}

func TestPackageName(t *testing.T) {
	tests := []struct {
		name string
		purl *PackageURL
		want string
	}{
		{
			name: "npm scoped",
			purl: &PackageURL{Type: "npm", Namespace: "@babel", Name: "core"},
			want: "@@babel/core",
		},
		{
			name: "npm unscoped",
			purl: &PackageURL{Type: "npm", Name: "express"},
			want: "express",
		},
		{
			name: "maven",
			purl: &PackageURL{Type: "maven", Namespace: "org.apache.commons", Name: "commons-lang3"},
			want: "org.apache.commons:commons-lang3",
		},
		{
			name: "golang",
			purl: &PackageURL{Type: "golang", Namespace: "github.com/go-chi/chi", Name: "v5"},
			want: "github.com/go-chi/chi/v5",
		},
		{
			name: "default type",
			purl: &PackageURL{Type: "cargo", Name: "serde"},
			want: "serde",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.purl.PackageName())
		})
	}
}

func TestEcosystemForType(t *testing.T) {
	tests := []struct {
		purlType string
		wantEco  string
		wantOK   bool
	}{
		{"npm", "npm", true},
		{"maven", "Maven", true},
		{"pypi", "PyPI", true},
		{"golang", "Go", true},
		{"cargo", "crates.io", true},
		{"nuget", "NuGet", true},
		{"gem", "RubyGems", true},
		{"composer", "Packagist", true},
		{"swift", "SwiftURL", true},
		{"cocoapods", "CocoaPods", true},
		{"pub", "Pub", true},
		{"hex", "Hex", true},
		{"unknown", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.purlType, func(t *testing.T) {
			eco, ok := EcosystemForType(tt.purlType)
			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantEco, eco)
		})
	}
}

func TestString(t *testing.T) {
	p := &PackageURL{
		Type:    "npm",
		Name:    "express",
		Version: "4.17.1",
	}
	s := p.String()
	assert.Contains(t, s, "pkg:npm/")
	assert.Contains(t, s, "express")
	assert.Contains(t, s, "@4.17.1")

	// Round-trip
	p2, err := Parse(s)
	assert.NoError(t, err)
	assert.Equal(t, p.Type, p2.Type)
	assert.Equal(t, p.Name, p2.Name)
	assert.Equal(t, p.Version, p2.Version)
}
