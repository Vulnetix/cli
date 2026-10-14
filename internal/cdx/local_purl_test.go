package cdx

import "testing"

// The package-url spec makes the npm scope the namespace and percent-encodes its @.
// pkg:npm/babel/traverse names a different package, so an advisory lookup by purl
// found nothing for any scoped dependency.
func TestBuildLocalPurlEncodesTheNpmScope(t *testing.T) {
	cases := map[string]string{
		"@babel/traverse|7.7.4": "pkg:npm/%40babel/traverse@7.7.4",
		"@babel/traverse|":      "pkg:npm/%40babel/traverse",
		"lodash|4.17.4":         "pkg:npm/lodash@4.17.4",
	}
	for in, want := range cases {
		name, version := in, ""
		for i := 0; i < len(in); i++ {
			if in[i] == '|' {
				name, version = in[:i], in[i+1:]
				break
			}
		}
		if got := BuildLocalPurl(name, version, "npm"); got != want {
			t.Errorf("BuildLocalPurl(%q,%q) = %q, want %q", name, version, got, want)
		}
	}
}

// A Swift package is host/owner/repo; the purl's namespace is host/owner. One escaped
// name left it without the namespace the spec and OSV require.
func TestBuildLocalPurlGivesSwiftPackagesANamespace(t *testing.T) {
	if got := BuildLocalPurl("github.com/apple/swift-nio", "2.40.0", "swift"); got != "pkg:swift/github.com/apple/swift-nio@2.40.0" {
		t.Errorf("got %q", got)
	}
	if got := BuildLocalPurl("github.com/apple/swift-nio", "", "swift"); got != "pkg:swift/github.com/apple/swift-nio" {
		t.Errorf("got %q", got)
	}
}
