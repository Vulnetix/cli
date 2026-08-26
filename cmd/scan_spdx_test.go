package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/vulnetix/cli/v3/internal/scan"
)

const spdxFixture = `{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "myapp-sbom",
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-requests",
      "name": "requests",
      "versionInfo": "2.32.3",
      "externalRefs": [
        {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:pypi/requests@2.32.3"}
      ]
    },
    {
      "SPDXID": "SPDXRef-Package-lodash",
      "name": "lodash",
      "versionInfo": "4.17.21",
      "externalRefs": [
        {"referenceCategory": "PACKAGE_MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/lodash@4.17.21"}
      ]
    },
    {
      "SPDXID": "SPDXRef-Package-nopurl",
      "name": "unmatchable",
      "versionInfo": "1.0.0"
    }
  ]
}`

// An SPDX document is an input format, not just something to list: its packages
// are scanned exactly as a CycloneDX input's components are. A package with no
// purl carries no ecosystem and cannot be matched, so it is dropped.
func TestParseSPDXForScan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sbom.spdx.json")
	if err := os.WriteFile(path, []byte(spdxFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	components, err := parseSPDXForScan(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(components) != 2 {
		t.Fatalf("components = %d, want 2: %+v", len(components), components)
	}

	pkgs := buildPackagesFromCDX(components, "sbom.spdx.json")
	byName := map[string]scan.ScopedPackage{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}
	req, ok := byName["requests"]
	if !ok || req.Version != "2.32.3" || req.Ecosystem != "pypi" || req.SourceFile != "sbom.spdx.json" {
		t.Errorf("requests = %+v, want 2.32.3 / pypi / sbom.spdx.json", req)
	}
	if lodash, ok := byName["lodash"]; !ok || lodash.Ecosystem != "npm" {
		t.Errorf("lodash = %+v, want npm", lodash)
	}
}

// The summary count is a dedup of what was scanned, not a filter on it: `db`
// (crystal), `qs` and `ms` (npm) are real packages, and dropping short names
// made the footer disagree with the SBOM and with the VDB query.
func TestCountUniquePackages_KeepsShortNames(t *testing.T) {
	packages := []scan.ScopedPackage{
		{Name: "db", Ecosystem: "crystal"},
		{Name: "qs", Ecosystem: "npm"},
		{Name: "kemal", Ecosystem: "crystal"},
		{Name: "kemal", Ecosystem: "crystal"}, // duplicate: same name+ecosystem
		{Name: "", Ecosystem: "npm"},          // unnamed: not a package
	}
	if got := countUniquePackages(packages); got != 3 {
		t.Errorf("countUniquePackages = %d, want 3", got)
	}
	if got := len(countUniqueMap(packages)); got != 3 {
		t.Errorf("countUniqueMap = %d entries, want 3", got)
	}
}
