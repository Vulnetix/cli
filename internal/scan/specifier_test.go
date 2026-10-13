package scan

import "testing"

func TestIsResolvedVersion(t *testing.T) {
	good := []string{"1.2.3", "0.135.1", "2.0.0rc1", "3.2.0.dev0", "v1.2.3", "2023.7.22", "1.0.0.RELEASE", "5.3.2+local", "1:2.4.5-1ubuntu1", "4.17.21"}
	bad := []string{"", " ", "latest", "next", "*", "catalog:", "workspace:*", "link:../x", "file:./pkg", "git+https://x/y.git",
		"github:user/repo", "${remoting.version}", "^1.2.3", "~1.2", ">=1.0 <2.0", "1.0 - 2.0", "1.x || 2.x", "[1.0,2.0)", "(,1.0]", "main", "npm:real@1.0.0"}
	for _, v := range good {
		if !IsResolvedVersion(v) {
			t.Errorf("%q names a release", v)
		}
	}
	for _, v := range bad {
		if IsResolvedVersion(v) {
			t.Errorf("%q is a specifier, not a release", v)
		}
	}
}

func TestStripGemPlatform(t *testing.T) {
	for in, want := range map[string]string{
		"1.19.1-x86_64-linux-gnu": "1.19.1",
		"1.19.1-arm64-darwin":     "1.19.1",
		"1.19.1-java":             "1.19.1",
		"1.19.1-x64-mingw-ucrt":   "1.19.1",
		"1.19.1":                  "1.19.1",
		"2.0.0.rc1":               "2.0.0.rc1",
		"1.2.3-beta":              "1.2.3-beta",
	} {
		if got := StripGemPlatform(in); got != want {
			t.Errorf("StripGemPlatform(%q) = %q, want %q", in, got, want)
		}
	}
}
