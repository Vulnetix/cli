package cmd

import (
	"testing"

	"github.com/vulnetix/cli/v3/internal/scan"
)

// A committed CycloneDX/SPDX SBOM (ManifestInfo == nil) is SCA content. It must
// be included when SCA is active but excluded for a container-only scan, so a
// `containers` run over a repo carrying an osv.cdx.json doesn't pull the SBOM's
// whole package set into the container component list.
func TestFilterFilesByFeature_CDXFollowsSCA(t *testing.T) {
	files := []scan.DetectedFile{
		{RelPath: "Containerfile", FileType: scan.FileTypeManifest,
			ManifestInfo: &scan.ManifestInfo{Type: "Dockerfile", Ecosystem: "docker", Language: "docker"}},
		{RelPath: "package.json", FileType: scan.FileTypeManifest,
			ManifestInfo: &scan.ManifestInfo{Type: "package.json", Ecosystem: "npm", Language: "javascript"}},
		{RelPath: ".repo/osv.cdx.json", FileType: scan.FileTypeCycloneDX}, // ManifestInfo nil
	}

	has := func(fs []scan.DetectedFile, rel string) bool {
		for _, f := range fs {
			if f.RelPath == rel {
				return true
			}
		}
		return false
	}

	// containers scope: noSCA=true, noContainers=false, noIAC=true
	cont := filterFilesByFeature(files, true, false, true)
	if !has(cont, "Containerfile") {
		t.Fatalf("containers scope must keep Containerfile; got %v", cont)
	}
	if has(cont, "package.json") {
		t.Fatalf("containers scope must drop SCA manifests; got %v", cont)
	}
	if has(cont, ".repo/osv.cdx.json") {
		t.Fatalf("containers scope must drop CDX SBOMs (SCA content); got %v", cont)
	}

	// sca scope: noSCA=false → CDX + npm kept, docker dropped
	sca := filterFilesByFeature(files, false, true, true)
	if !has(sca, ".repo/osv.cdx.json") {
		t.Fatalf("sca scope must keep CDX SBOMs; got %v", sca)
	}
	if !has(sca, "package.json") {
		t.Fatalf("sca scope must keep npm manifests; got %v", sca)
	}
	if has(sca, "Containerfile") {
		t.Fatalf("sca scope must drop docker manifests; got %v", sca)
	}

	// generic scan (all features on) returns everything untouched.
	all := filterFilesByFeature(files, false, false, false)
	if len(all) != len(files) {
		t.Fatalf("all-features scope must pass through; got %d want %d", len(all), len(files))
	}
}
