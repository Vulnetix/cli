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
