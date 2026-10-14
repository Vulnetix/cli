package license

import "testing"

func TestStoredLicensesFillOnlyUnknownPackages(t *testing.T) {
	var asked []string
	StoredLicenses = func(pkgs []PackageLicense) map[int]string {
		out := map[int]string{}
		for i, p := range pkgs {
			asked = append(asked, p.PackageName)
			if p.PackageName == "known-remotely" {
				out[i] = "Apache-2.0"
			}
		}
		return out
	}
	defer func() { StoredLicenses = nil }()

	pkgs := []PackageLicense{
		{PackageName: "local", LicenseSpdxID: "MIT", LicenseSource: "manifest"},
		{PackageName: "known-remotely", LicenseSpdxID: "UNKNOWN"},
		{PackageName: "unknown-everywhere", LicenseSpdxID: "UNKNOWN"},
	}
	applyStoredLicenses(pkgs)

	if len(asked) != 2 || asked[0] != "known-remotely" || asked[1] != "unknown-everywhere" {
		t.Fatalf("asked about %v; only unresolved packages should be asked", asked)
	}
	if pkgs[0].LicenseSpdxID != "MIT" || pkgs[0].LicenseSource != "manifest" {
		t.Fatalf("a locally resolved licence was replaced: %+v", pkgs[0])
	}
	if pkgs[1].LicenseSpdxID != "Apache-2.0" || pkgs[1].LicenseSource != "vulnetix" || pkgs[1].Record == nil {
		t.Fatalf("stored licence not applied: %+v", pkgs[1])
	}
	if pkgs[2].LicenseSpdxID != "UNKNOWN" {
		t.Fatalf("a package the API does not know was changed: %+v", pkgs[2])
	}
}
