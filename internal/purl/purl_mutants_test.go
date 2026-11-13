package purl

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These cases pin the branches gremlins found unguarded in purl.go: each one
// fails when the condition it names is negated or its boundary moved.

// A PURL with no slash after the type has no name, so Parse must refuse it
// with the "missing type or name" error rather than slicing at index -1.
func TestParseWithoutTypeSlashIsMissingTypeOrName(t *testing.T) {
	for _, in := range []string{"pkg:maven", "pkg:npm@1.0.0", "pkg:pypi?arch=x86_64", "pkg:golang#sub"} {
		t.Run(in, func(t *testing.T) {
			p, err := Parse(in)
			require.Error(t, err)
			assert.Nil(t, p)
			assert.Contains(t, err.Error(), "missing type or name")
		})
	}
}

// The slash that separates the type is the first one: the type is everything
// before it and is lower-cased, the rest is namespace and name.
func TestParseSplitsTypeAtTheFirstSlash(t *testing.T) {
	p, err := Parse("pkg:Maven/org.example/lib@1.0")
	require.NoError(t, err)
	assert.Equal(t, "maven", p.Type)
	assert.Equal(t, "org.example", p.Namespace)
	assert.Equal(t, "lib", p.Name)
}

// Each typed branch of PackageName joins the namespace only when there is
// one; without a namespace it must return the bare name.
func TestPackageNameWithAndWithoutNamespace(t *testing.T) {
	tests := []struct {
		name string
		purl PackageURL
		want string
	}{
		{"npm without namespace", PackageURL{Type: "npm", Name: "core"}, "core"},
		{"npm with namespace", PackageURL{Type: "npm", Namespace: "babel", Name: "core"}, "@babel/core"},
		{"maven without namespace", PackageURL{Type: "maven", Name: "commons-lang3"}, "commons-lang3"},
		{"maven with namespace", PackageURL{Type: "maven", Namespace: "org.apache.commons", Name: "commons-lang3"}, "org.apache.commons:commons-lang3"},
		{"golang without namespace", PackageURL{Type: "golang", Name: "chi"}, "chi"},
		{"golang with namespace", PackageURL{Type: "golang", Namespace: "github.com/go-chi", Name: "chi"}, "github.com/go-chi/chi"},
		{"other type ignores namespace", PackageURL{Type: "cargo", Namespace: "ns", Name: "serde"}, "serde"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.purl.PackageName())
		})
	}
}

// String writes "?" only when there are qualifiers and "#" only when there is
// a subpath; the exact output is pinned so a negated or off-by-one check on
// either shows up.
func TestStringQualifiersAndSubpath(t *testing.T) {
	tests := []struct {
		name string
		purl PackageURL
		want string
	}{
		{"bare", PackageURL{Type: "npm", Name: "express"}, "pkg:npm/express"},
		{"empty qualifier map", PackageURL{Type: "npm", Name: "express", Version: "4.17.1", Qualifiers: map[string]string{}}, "pkg:npm/express@4.17.1"},
		{"one qualifier", PackageURL{Type: "deb", Namespace: "debian", Name: "curl", Version: "7.88.1", Qualifiers: map[string]string{"arch": "amd64"}}, "pkg:deb/debian/curl@7.88.1?arch=amd64"},
		{"subpath", PackageURL{Type: "golang", Namespace: "github.com/x", Name: "y", Version: "v1.0.0", Subpath: "cmd"}, "pkg:golang/github.com%2Fx/y@v1.0.0#cmd"},
		{"qualifier and subpath", PackageURL{Type: "npm", Name: "express", Version: "1.0.0", Qualifiers: map[string]string{"k": "v"}, Subpath: "src"}, "pkg:npm/express@1.0.0?k=v#src"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.purl.String())
		})
	}
}

// Two qualifiers are joined with "&" (map order is not fixed, so the pair is
// read back rather than compared as a string).
func TestStringJoinsSeveralQualifiers(t *testing.T) {
	p := PackageURL{Type: "deb", Name: "curl", Qualifiers: map[string]string{"arch": "amd64", "distro": "bookworm"}}
	s := p.String()
	assert.Contains(t, s, "&")
	back, err := Parse(s)
	require.NoError(t, err)
	assert.Equal(t, p.Qualifiers, back.Qualifiers)
}
