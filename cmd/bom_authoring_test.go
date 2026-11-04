package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cyclonedx "github.com/Vulnetix/vdb-cyclonedx"
	"github.com/spf13/cobra"

	"github.com/vulnetix/cli/v4/internal/scanopts"
)

// resetAuthoringFlags puts the customisation flags back to unset, because flag
// values live on the command object and would leak into later tests.
func resetAuthoringFlags(t *testing.T, cmd *cobra.Command) {
	t.Helper()
	for _, name := range scanopts.AuthorshipFlags {
		f := cmd.Flags().Lookup(name)
		if f == nil {
			continue
		}
		if sv, ok := f.Value.(interface{ Replace([]string) error }); ok {
			_ = sv.Replace(nil)
		} else {
			_ = f.Value.Set(f.DefValue)
		}
		f.Changed = false
	}
	for _, name := range []string{"project", "cluster", "namespace", "environment", "sign"} {
		if f := cmd.Flags().Lookup(name); f != nil {
			_ = f.Value.Set(f.DefValue)
			f.Changed = false
		}
	}
}

// The three generators author documents, so all three accept the same identity,
// customisation, deployment and signing flags. The transformer-tier commands,
// which enrich documents somebody else authored, accept none of them.
func TestGeneratorsShareAuthorshipFlags(t *testing.T) {
	for _, c := range []*cobra.Command{cdxCmd, aibomCmd, cbomCmd} {
		for _, name := range append(append([]string{}, scanopts.AuthorshipFlags...), "project", "cluster", "namespace", "environment", "tag", "sign") {
			if c.Flags().Lookup(name) == nil {
				t.Errorf("%s lacks --%s", c.Name(), name)
			}
		}
	}
	for _, c := range []*cobra.Command{bomEnrichCmd, bomImportCmd} {
		for _, name := range []string{"bom-author", "bom-overlay", "bom-manufacturer", "lifecycle"} {
			if c.Flags().Lookup(name) != nil {
				t.Errorf("%s registers --%s, but a transformer has no authorship to claim", c.Name(), name)
			}
		}
	}
}

type authoredDoc struct {
	SerialNumber string `json:"serialNumber"`
	Version      int    `json:"version"`
	SpecVersion  string `json:"specVersion"`
	Metadata     struct {
		Manufacturer *struct {
			Name string   `json:"name"`
			URL  []string `json:"url"`
		} `json:"manufacturer"`
		Authors  []struct{ Name, Email string } `json:"authors"`
		Supplier *struct {
			Name string   `json:"name"`
			URL  []string `json:"url"`
		} `json:"supplier"`
		Component struct {
			Type, Name, Version, Group, Purl string
			BOMRef                           string                                  `json:"bom-ref"`
			Supplier                         *struct{ Name string }                  `json:"supplier"`
			Licenses                         []struct{ License struct{ ID string } } `json:"licenses"`
		} `json:"component"`
		Licenses   []struct{ License struct{ ID string } } `json:"licenses"`
		Properties []struct{ Name, Value string }          `json:"properties"`
		Lifecycles []struct{ Phase string }                `json:"lifecycles"`
		Tools      struct {
			Components []struct{ Name string } `json:"components"`
		} `json:"tools"`
	} `json:"metadata"`
	Components []struct {
		Type, Name, Version string
		BOMRef              string                 `json:"bom-ref"`
		Supplier            *struct{ Name string } `json:"supplier"`
	} `json:"components"`
	Dependencies []struct {
		Ref       string   `json:"ref"`
		DependsOn []string `json:"dependsOn"`
	} `json:"dependencies"`
	Services     []map[string]any `json:"services"`
	Compositions []map[string]any `json:"compositions"`
	Annotations  []map[string]any `json:"annotations"`
}

func (d authoredDoc) metaProp(name string) string {
	for _, p := range d.Metadata.Properties {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

func TestCDXAuthoringFlagsAndOverlay(t *testing.T) {
	for _, spec := range []string{"1.6", "1.7"} {
		t.Run("spec "+spec, func(t *testing.T) {
			resetSBOMFlags(t)
			resetAuthoringFlags(t, cdxCmd)
			t.Cleanup(func() { resetAuthoringFlags(t, cdxCmd) })
			root := sbomFixture(t)
			out := filepath.Join(root, "out.cdx.json")
			overlay, _ := filepath.Abs("testdata/bom/overlay.cdx.json")

			if _, err := executeCommand(t, rootCmd, "cdx",
				"--path", root, "--output-file", out, "--spec-version", spec,
				"--no-aibom", "--no-cbom", "--no-analytics", "--no-banner",
				"--bom-manufacturer", "Acme Ltd", "--bom-manufacturer-url", "https://acme.example",
				"--bom-author", "Jane Doe <jane@acme.example>",
				"--bom-supplier", "Acme Supply", "--bom-supplier-url", "https://supply.acme.example",
				"--bom-serial", "release-2026.11", "--bom-version", "3",
				"--bom-license", "MIT", "--bom-property", "acme:team=payments",
				"--component-name", "svc", "--component-version", "2.0.0", "--component-group", "acme",
				"--component-purl", "pkg:generic/acme/svc@2.0.0",
				"--lifecycle", "build,operations",
				"--bom-overlay", overlay,
			); err != nil {
				t.Fatalf("cdx: %v", err)
			}

			raw, err := os.ReadFile(out)
			if err != nil {
				t.Fatal(err)
			}
			if _, violations, err := cyclonedx.ValidateCycloneDX(raw); err != nil || len(violations) > 0 {
				t.Fatalf("the written document does not validate at %s: %v %+v", spec, err, violations)
			}
			var doc authoredDoc
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			if doc.SpecVersion != spec {
				t.Errorf("specVersion = %s", doc.SpecVersion)
			}
			if want := cyclonedx.NormalizeSerialNumber("release-2026.11"); doc.SerialNumber != want || doc.Version != 3 {
				t.Errorf("serial/version = %s/%d, want %s/3", doc.SerialNumber, doc.Version, want)
			}
			m := doc.Metadata
			if m.Manufacturer == nil || m.Manufacturer.Name != "Acme Ltd" || len(m.Manufacturer.URL) != 1 || m.Manufacturer.URL[0] != "https://acme.example" {
				t.Errorf("metadata.manufacturer = %+v", m.Manufacturer)
			}
			if len(m.Authors) != 1 || m.Authors[0].Name != "Jane Doe" || m.Authors[0].Email != "jane@acme.example" {
				t.Errorf("metadata.authors = %+v", m.Authors)
			}
			if m.Supplier == nil || m.Supplier.Name != "Acme Supply" || len(m.Supplier.URL) != 1 {
				t.Errorf("metadata.supplier = %+v", m.Supplier)
			}
			c := m.Component
			if c.Name != "svc" || c.Version != "2.0.0" || c.Group != "acme" || c.Purl != "pkg:generic/acme/svc@2.0.0" || c.BOMRef != "urn:project" || c.Type != "application" {
				t.Errorf("metadata.component = %+v", c)
			}
			if c.Supplier == nil || c.Supplier.Name != "Acme Supplier" || len(c.Licenses) != 1 || c.Licenses[0].License.ID != "Apache-2.0" {
				t.Errorf("metadata.component overlay members = supplier %+v licenses %+v", c.Supplier, c.Licenses)
			}
			ids := []string{}
			for _, l := range m.Licenses {
				ids = append(ids, l.License.ID)
			}
			if strings.Join(ids, ",") != "CC0-1.0,MIT" {
				t.Errorf("metadata.licenses = %v, want the overlay's then the flag's", ids)
			}
			if doc.metaProp("acme:team") != "payments" || doc.metaProp("acme:owner") != "payments" {
				t.Errorf("metadata.properties = %+v", m.Properties)
			}
			phases := []string{}
			for _, l := range m.Lifecycles {
				phases = append(phases, l.Phase)
			}
			if strings.Join(phases, ",") != "build,operations" {
				t.Errorf("lifecycles = %v", phases)
			}
			if len(m.Tools.Components) != 1 || m.Tools.Components[0].Name != cyclonedx.ToolCDX {
				t.Errorf("metadata.tools = %+v", m.Tools.Components)
			}

			var leftPad, firmware bool
			for _, comp := range doc.Components {
				switch comp.Name {
				case "left-pad":
					leftPad = comp.Supplier != nil && comp.Supplier.Name == "Left Pad Org"
				case "board-fw":
					firmware = comp.Type == "firmware" && comp.BOMRef == "fw:board"
				}
			}
			if !leftPad || !firmware {
				t.Errorf("components: left-pad supplier applied=%v, firmware appended=%v", leftPad, firmware)
			}
			var rootDeps []string
			for _, d := range doc.Dependencies {
				if d.Ref == "urn:project" {
					rootDeps = d.DependsOn
				}
			}
			var hasFW bool
			for _, d := range rootDeps {
				hasFW = hasFW || d == "fw:board"
			}
			if !hasFW {
				t.Errorf("urn:project dependencies lack fw:board: %v", rootDeps)
			}
			if len(doc.Services) != 1 || len(doc.Compositions) != 1 || len(doc.Annotations) != 1 {
				t.Errorf("services/compositions/annotations = %d/%d/%d, want 1 each", len(doc.Services), len(doc.Compositions), len(doc.Annotations))
			}
		})
	}
}

func TestCDXRejectsASignedOverlayBeforeScanning(t *testing.T) {
	resetSBOMFlags(t)
	resetAuthoringFlags(t, cdxCmd)
	t.Cleanup(func() { resetAuthoringFlags(t, cdxCmd) })
	root := sbomFixture(t)
	overlay, _ := filepath.Abs("testdata/bom/bad-signature.cdx.json")
	_, err := executeCommand(t, rootCmd, "cdx", "--path", root, "--no-aibom", "--no-cbom", "--no-analytics", "--no-banner", "--bom-overlay", overlay)
	if err == nil || !strings.Contains(err.Error(), "/signature") {
		t.Fatalf("want an error naming /signature, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, ".vulnetix", "sbom.cdx.json")); statErr == nil {
		t.Error("a document was written despite the rejected overlay")
	}
}

func TestCDXAuthoringFromEnvironment(t *testing.T) {
	resetSBOMFlags(t)
	resetAuthoringFlags(t, cdxCmd)
	t.Cleanup(func() { resetAuthoringFlags(t, cdxCmd) })
	t.Setenv(scanopts.AuthorsEnv, "A <a@x.example>; B")
	t.Setenv(scanopts.SupplierEnv, "Env Supply")
	root := sbomFixture(t)
	out := filepath.Join(root, "out.cdx.json")
	if _, err := executeCommand(t, rootCmd, "cdx", "--path", root, "--output-file", out, "--no-aibom", "--no-cbom", "--no-analytics", "--no-banner"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(out)
	var doc authoredDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Metadata.Authors) != 2 || doc.Metadata.Authors[1].Name != "B" || doc.Metadata.Supplier == nil || doc.Metadata.Supplier.Name != "Env Supply" {
		t.Errorf("authors = %+v supplier = %+v", doc.Metadata.Authors, doc.Metadata.Supplier)
	}
}

// cdx carries findings over from the file it rewrites. An overlay's analysis on
// one of them must survive that, not be replaced by the copy on disk.
func TestCDXOverlayAnalysisOnACarriedOverFinding(t *testing.T) {
	resetSBOMFlags(t)
	resetAuthoringFlags(t, cdxCmd)
	t.Cleanup(func() { resetAuthoringFlags(t, cdxCmd) })
	root := sbomFixture(t)
	out := filepath.Join(root, "out.cdx.json")
	base := []string{"cdx", "--path", root, "--output-file", out, "--no-aibom", "--no-cbom", "--no-analytics", "--no-banner"}
	if _, err := executeCommand(t, rootCmd, base...); err != nil {
		t.Fatal(err)
	}
	// An earlier scan recorded a finding on left-pad.
	raw, _ := os.ReadFile(out)
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["vulnerabilities"] = []any{map[string]any{"id": "CVE-2099-0001", "bom-ref": "vuln:CVE-2099-0001",
		"affects": []any{map[string]any{"ref": "pkg:npm/left-pad@1.3.0"}}}}
	raw, _ = json.MarshalIndent(doc, "", "  ")
	if err := os.WriteFile(out, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	overlay, _ := filepath.Abs("testdata/bom/analysis-overlay.cdx.json")
	resetSBOMFlags(t)
	if _, err := executeCommand(t, rootCmd, append(base, "--bom-overlay", overlay)...); err != nil {
		t.Fatal(err)
	}
	raw, _ = os.ReadFile(out)
	var got struct {
		Vulnerabilities []struct {
			ID       string                                 `json:"id"`
			Affects  []struct{ Ref string }                 `json:"affects"`
			Analysis *struct{ State, Justification string } `json:"analysis"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Vulnerabilities) != 1 {
		t.Fatalf("vulnerabilities = %+v, want the one carried-over finding", got.Vulnerabilities)
	}
	v := got.Vulnerabilities[0]
	if v.Analysis == nil || v.Analysis.State != "not_affected" || v.Analysis.Justification != "code_not_reachable" || len(v.Affects) != 1 {
		t.Errorf("finding = %+v, want the overlay's analysis on the carried-over affects", v)
	}
}
