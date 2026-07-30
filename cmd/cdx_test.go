package cmd

import (
	"archive/zip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sbomFixture writes a project that exercises every non-binary discovery source:
// a manifest, a GitHub Actions workflow, a shell script and a Dockerfile.
func sbomFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"package.json":             `{"name":"demo","version":"1.0.0","license":"MIT","dependencies":{"left-pad":"1.3.0"}}`,
		".github/workflows/ci.yml": "on: push\njobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n      - run: pip install requests==2.32.0\n",
		"scripts/setup.sh":         "#!/bin/bash\napk add --no-cache jq\n",
		"Dockerfile":               "FROM alpine:3.20\nRUN apk add --no-cache openssl\n",
		".circleci/config.yml":     "version: 2.1\njobs:\n  build:\n    steps:\n      - run: npm install -g pnpm@9.1.0\n",
	}
	for rel, body := range files {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// resetSBOMFlags restores the cdx command's flags to their defaults. Cobra flag
// values live on the command object, so a test that disables a discovery pass
// would otherwise disable it for every test that runs after it.
func resetSBOMFlags(t *testing.T) {
	t.Helper()
	defaults := map[string]string{
		"path":                 ".",
		"output":               "pretty",
		"output-file":          "",
		"spec-version":         "1.7",
		"no-manifests":         "false",
		"no-filesystem":        "false",
		"no-containerfiles":    "false",
		"no-ci":                "false",
		"no-shell":             "false",
		"no-binary-analysis":   "false",
		"no-binary-packages":   "false",
		"no-licenses":          "false",
		"no-aibom":             "false",
		"no-cbom":              "false",
		"no-signatures":        "false",
		"include-home":         "false",
		"sbom-include-ignored": "false",
		"cdx-include-ignored":  "false",
	}
	for name, value := range defaults {
		if err := cdxCmd.Flags().Set(name, value); err != nil {
			t.Fatalf("resetting --%s: %v", name, err)
		}
	}
	for _, name := range []string{"container-rootfs", "container-archive", "exclude", "ignore"} {
		f := cdxCmd.Flags().Lookup(name)
		if f == nil {
			continue
		}
		if sv, ok := f.Value.(interface{ Replace([]string) error }); ok {
			if err := sv.Replace(nil); err != nil {
				t.Fatalf("resetting --%s: %v", name, err)
			}
		}
	}
}

type sbomDoc struct {
	BOMFormat  string `json:"bomFormat"`
	Components []struct {
		Type       string `json:"type"`
		BOMRef     string `json:"bom-ref"`
		Name       string `json:"name"`
		Version    string `json:"version"`
		Purl       string `json:"purl"`
		Properties []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"properties"`
		Licenses []struct {
			License *struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"license"`
		} `json:"licenses"`
	} `json:"components"`
	Dependencies []struct {
		Ref       string   `json:"ref"`
		DependsOn []string `json:"dependsOn"`
	} `json:"dependencies"`
	Vulnerabilities []map[string]any `json:"vulnerabilities"`
}

func readSBOM(t *testing.T, path string) sbomDoc {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var doc sbomDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	return doc
}

func (d sbomDoc) prop(name, prop string) string {
	for _, c := range d.Components {
		if c.Name != name {
			continue
		}
		for _, p := range c.Properties {
			if p.Name == prop {
				return p.Value
			}
		}
	}
	return ""
}

func (d sbomDoc) evidence(name string) []string {
	var out []string
	for _, c := range d.Components {
		if c.Name != name {
			continue
		}
		for _, p := range c.Properties {
			if p.Name == "vulnetix:sbom/evidence" {
				out = append(out, p.Value)
			}
		}
	}
	return out
}

func TestSBOMCommandCoversEveryDiscoverySource(t *testing.T) {
	resetSBOMFlags(t)
	root := sbomFixture(t)
	out := filepath.Join(root, "out.cdx.json")

	if _, err := executeCommand(t, rootCmd, "cdx",
		"--path", root, "--output-file", out,
		"--no-aibom", "--no-cbom", "--no-analytics", "--no-banner",
	); err != nil {
		t.Fatalf("cdx: %v", err)
	}

	doc := readSBOM(t, out)
	if doc.BOMFormat != "CycloneDX" {
		t.Fatalf("bomFormat = %q", doc.BOMFormat)
	}
	purls := map[string]bool{}
	for _, c := range doc.Components {
		purls[c.Purl] = true
	}
	for _, want := range []string{
		"pkg:npm/left-pad@1.3.0",   // manifest
		"pkg:pypi/requests@2.32.0", // GitHub Actions `run:` step
		"pkg:apk/jq",               // shell script
		"pkg:apk/openssl",          // Dockerfile RUN
		"pkg:oci/alpine@3.20",      // Dockerfile FROM
		"pkg:npm/pnpm@9.1.0",       // CircleCI pipeline
	} {
		if !purls[want] {
			t.Errorf("missing component %s (have %v)", want, purls)
		}
	}

	// Source types distinguish declared dependencies from inferred install commands.
	if got := doc.prop("left-pad", "vulnetix:source-type"); got != "manifest" {
		t.Errorf("left-pad source-type = %q, want manifest", got)
	}
	if got := doc.prop("jq", "vulnetix:source-type"); got != "command" {
		t.Errorf("jq source-type = %q, want command", got)
	}

	// Evidence confidence: a declared dependency is high; an unpinned install
	// command is low; a pinned one is medium.
	assertEvidence := func(name, wantConfidence, wantLocator string) {
		t.Helper()
		ev := doc.evidence(name)
		if len(ev) == 0 {
			t.Errorf("%s has no evidence", name)
			return
		}
		if !strings.Contains(ev[0], wantConfidence) || !strings.Contains(ev[0], wantLocator) {
			t.Errorf("%s evidence = %q, want confidence %q and locator %q", name, ev[0], wantConfidence, wantLocator)
		}
	}
	assertEvidence("left-pad", "high", "package.json")
	assertEvidence("jq", "low", "scripts/setup.sh")
	assertEvidence("requests", "medium", ".github/workflows/ci.yml")

	// License detection ran and produced an SPDX id, not free text.
	var leftPadLicense string
	for _, c := range doc.Components {
		if c.Name == "left-pad" && len(c.Licenses) == 1 && c.Licenses[0].License != nil {
			leftPadLicense = c.Licenses[0].License.ID
		}
	}
	if leftPadLicense == "" {
		t.Error("left-pad has no SPDX license id")
	}

	// The project component owns the direct dependencies.
	var rootDeps []string
	for _, d := range doc.Dependencies {
		if d.Ref == "urn:project" {
			rootDeps = d.DependsOn
		}
	}
	if len(rootDeps) == 0 {
		t.Fatalf("no urn:project dependency edges: %+v", doc.Dependencies)
	}
}

func TestCDXCommandKeepsSBOMAliasAndGatesSources(t *testing.T) {
	resetSBOMFlags(t)
	root := sbomFixture(t)
	out := filepath.Join(root, "gated.cdx.json")

	// The `sbom` alias resolves to this command, and the matching
	// --sbom-include-ignored spelling of the flag is accepted alongside the
	// canonical --cdx-include-ignored.
	if _, err := executeCommand(t, rootCmd, "sbom",
		"--path", root, "--output-file", out,
		"--no-ci", "--no-shell", "--no-containerfiles", "--no-binary-analysis",
		"--sbom-include-ignored",
		"--no-aibom", "--no-cbom", "--no-analytics", "--no-banner",
	); err != nil {
		t.Fatalf("sbom alias: %v", err)
	}

	doc := readSBOM(t, out)
	for _, c := range doc.Components {
		if got := docSourceType(c.Properties); got == "command" {
			t.Errorf("component %s came from a command source that was disabled", c.Name)
		}
	}
	found := false
	for _, c := range doc.Components {
		if c.Purl == "pkg:npm/left-pad@1.3.0" {
			found = true
		}
	}
	if !found {
		t.Error("manifest packages must still be present when only command sources are disabled")
	}
}

func docSourceType(props []struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}) string {
	for _, p := range props {
		if p.Name == "vulnetix:source-type" {
			return p.Value
		}
	}
	return ""
}

func TestPreserveCDXVulnerabilitiesKeepsFindingsAndReferencedComponents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sbom.cdx.json")

	existing := `{
	  "bomFormat": "CycloneDX",
	  "specVersion": "1.7",
	  "serialNumber": "urn:uuid:5f2b0d2c-0000-4000-8000-000000000001",
	  "version": 1,
	  "components": [
	    {"type":"library","bom-ref":"pkg:npm/gone@0.0.1","name":"gone","version":"0.0.1","purl":"pkg:npm/gone@0.0.1"}
	  ],
	  "vulnerabilities": [
	    {"bom-ref":"CVE-2020-0001","id":"CVE-2020-0001","affects":[{"ref":"pkg:npm/gone@0.0.1"}],
	     "analysis":{"state":"resolved","response":["update"]}}
	  ]
	}`
	if err := os.WriteFile(path, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	fresh := `{
	  "bomFormat": "CycloneDX",
	  "specVersion": "1.7",
	  "serialNumber": "urn:uuid:5f2b0d2c-0000-4000-8000-000000000002",
	  "version": 1,
	  "components": [
	    {"type":"library","bom-ref":"pkg:npm/kept@1.0.0","name":"kept","version":"1.0.0","purl":"pkg:npm/kept@1.0.0"}
	  ]
	}`
	merged, count, err := preserveCDXVulnerabilities(path, []byte(fresh))
	if err != nil {
		t.Fatalf("preserveCDXVulnerabilities: %v", err)
	}
	if count != 1 {
		t.Fatalf("preserved %d vulnerabilities, want 1", count)
	}

	var doc sbomDoc
	if err := json.Unmarshal(merged, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vulnerabilities) != 1 || doc.Vulnerabilities[0]["id"] != "CVE-2020-0001" {
		t.Fatalf("vulnerabilities = %+v", doc.Vulnerabilities)
	}
	names := map[string]bool{}
	for _, c := range doc.Components {
		names[c.Name] = true
	}
	if !names["kept"] || !names["gone"] {
		t.Fatalf("components = %v, want both the fresh and the referenced-but-gone one", names)
	}
	if got := doc.prop("gone", "vulnetix:sbom/carried-over"); got != "true" {
		t.Errorf("carried-over marker = %q, want true", got)
	}

	// No existing file: the fresh document is returned untouched.
	out, count, err := preserveCDXVulnerabilities(filepath.Join(dir, "absent.json"), []byte(fresh))
	if err != nil || count != 0 || string(out) != fresh {
		t.Fatalf("absent file: count=%d err=%v changed=%v", count, err, string(out) != fresh)
	}

	// A file with no vulnerabilities contributes nothing.
	empty := filepath.Join(dir, "empty.cdx.json")
	if err := os.WriteFile(empty, []byte(fresh), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, count, err = preserveCDXVulnerabilities(empty, []byte(fresh)); err != nil || count != 0 {
		t.Fatalf("empty vulnerabilities: count=%d err=%v", count, err)
	}
}

// TestSBOMCommandInspectsContainerRootfs covers the container path: OS packages
// from the package database, packages recovered from an artefact inside the image,
// file-ownership attribution, and the flag on a binary no package claims.
func TestSBOMCommandInspectsContainerRootfs(t *testing.T) {
	resetSBOMFlags(t)
	root := t.TempDir()
	rootfs := filepath.Join(root, "rootfs")
	writeRootfsFile := func(rel, body string) {
		full := filepath.Join(rootfs, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeRootfsFile("var/lib/dpkg/status", "Package: libowned-java\nVersion: 1.2.3-1\nStatus: install ok installed\n\n")
	writeRootfsFile("var/lib/dpkg/info/libowned-java.list", "/.\n/usr/share/java\n/usr/share/java/owned.jar\n")
	writeJarWithCoordinates(t, filepath.Join(rootfs, "usr", "share", "java", "owned.jar"), "org.owned", "owned", "1.2.3")
	writeJarWithCoordinates(t, filepath.Join(rootfs, "opt", "vendor", "agent.jar"), "com.vendor", "agent", "9.9.9")

	out := filepath.Join(root, "image.cdx.json")
	if _, err := executeCommand(t, rootCmd, "cdx",
		"--path", root, "--container-rootfs", rootfs, "--output-file", out,
		"--no-aibom", "--no-cbom", "--no-analytics", "--no-banner",
	); err != nil {
		t.Fatalf("cdx --container-rootfs: %v", err)
	}

	doc := readSBOM(t, out)
	purls := map[string]bool{}
	for _, c := range doc.Components {
		purls[c.Purl] = true
	}
	for _, want := range []string{
		"pkg:deb/libowned-java@1.2.3-1",    // package database
		"pkg:maven/org.owned/owned@1.2.3",  // coordinates inside the owned jar
		"pkg:maven/com.vendor/agent@9.9.9", // coordinates inside the unpackaged jar
	} {
		if !purls[want] {
			t.Errorf("missing %s (have %v)", want, purls)
		}
	}
	if got := doc.prop("org.owned:owned", "vulnetix:source-type"); got != "binary" {
		t.Errorf("jar-derived package source-type = %q, want binary", got)
	}
	if ev := doc.evidence("org.owned:owned"); len(ev) == 0 || !strings.Contains(ev[0], "jvm-archive") {
		t.Errorf("jar evidence = %v, want the jvm-archive method", ev)
	}
	// Ownership only makes sense for artefacts the package database claims.
	if got := doc.prop("com.vendor:agent", "vulnetix:binary/discovered-in"); !strings.Contains(got, "agent.jar") {
		t.Errorf("discovered-in = %q, want the artefact path", got)
	}
}

func writeJarWithCoordinates(t *testing.T, path, group, artifact, version string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("META-INF/maven/" + group + "/" + artifact + "/pom.properties")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("groupId=" + group + "\nartifactId=" + artifact + "\nversion=" + version + "\n")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}
