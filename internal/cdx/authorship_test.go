package cdx

import (
	"strings"
	"testing"

	cyclonedx "github.com/Vulnetix/vdb-cyclonedx"
	"github.com/vulnetix/cli/v4/internal/gitctx"
)

func TestResolveManufacturerCascade(t *testing.T) {
	git := &gitctx.GitContext{RemoteURLs: []string{"git@github.com:acme-from-git/repo.git"}}

	cases := []struct {
		name string
		src  ManufacturerSources
		want string
	}{
		{
			name: "explicit override wins over everything",
			src:  ManufacturerSources{Override: "Explicit Ltd", Env: "Env Ltd", CIOwner: "ci-owner", Git: git},
			want: "Explicit Ltd",
		},
		{
			name: "environment beats CI and git",
			src:  ManufacturerSources{Env: "Env Ltd", CIOwner: "ci-owner", Git: git},
			want: "Env Ltd",
		},
		{
			name: "CI provider beats git",
			src:  ManufacturerSources{CIOwner: "ci-owner", Git: git},
			want: "ci-owner",
		},
		{
			name: "git remote is the last resort",
			src:  ManufacturerSources{Git: git},
			want: "acme-from-git",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveManufacturer(tc.src)
			if got == nil {
				t.Fatalf("resolved to nil, want %q", tc.want)
			}
			if got.Name != tc.want {
				t.Errorf("manufacturer = %q, want %q", got.Name, tc.want)
			}
		})
	}
}

// The important half of the cascade. CycloneDX's metadata.manufacturer is a
// claim about who created the document; an absent one costs a consumer a single
// unknown, whereas an invented one is a false statement they cannot detect.
func TestResolveManufacturerReturnsNilRatherThanGuessing(t *testing.T) {
	if got := ResolveManufacturer(ManufacturerSources{}); got != nil {
		t.Fatalf("invented a manufacturer from nothing: %#v", got)
	}
	if got := ResolveManufacturer(ManufacturerSources{Git: &gitctx.GitContext{}}); got != nil {
		t.Fatalf("invented a manufacturer from an empty repository: %#v", got)
	}
	// An org id alone identifies a Vulnetix organisation but supplies no name to
	// print, and manufacturer.name is what a reader sees.
	if got := ResolveManufacturer(ManufacturerSources{OrgID: "0189a5c8-0000-7000-8000-000000000000"}); got != nil {
		t.Fatalf("named an organization from an id alone: %#v", got)
	}
}

func TestResolveManufacturerCarriesOrgIDAsBOMRef(t *testing.T) {
	got := ResolveManufacturer(ManufacturerSources{
		CIOwner: "acme",
		OrgID:   "0189a5c8-0000-7000-8000-000000000000",
	})
	if got == nil || got.BOMRef != "urn:uuid:0189a5c8-0000-7000-8000-000000000000" {
		t.Fatalf("bom-ref = %#v", got)
	}
}

// The phase is a statement about the observation, and every builder used to
// hardcode `build` regardless of what it had actually read.
func TestDerivePhases(t *testing.T) {
	cases := []struct {
		name string
		src  LifecycleSources
		want []LifecyclePhase
	}{
		{
			name: "manifests alone are pre-build: the artefacts do not exist yet",
			src:  LifecycleSources{Manifests: true},
			want: []LifecyclePhase{PhasePreBuild},
		},
		{
			name: "an installed tree is what a build resolved",
			src:  LifecycleSources{InstalledTree: true},
			want: []LifecyclePhase{PhaseBuild},
		},
		{
			name: "a container image is something already built",
			src:  LifecycleSources{ContainerImage: true},
			want: []LifecyclePhase{PhasePostBuild},
		},
		{
			name: "compiled artefacts are post-build too",
			src:  LifecycleSources{CompiledArtifacts: true},
			want: []LifecyclePhase{PhasePostBuild},
		},
		{
			name: "AI and crypto inventories identify assets by observation",
			src:  LifecycleSources{Discovery: true},
			want: []LifecyclePhase{PhaseDiscovery},
		},
		{
			name: "deployment labels say this describes something running",
			src:  LifecycleSources{Manifests: true, Deployed: true},
			want: []LifecyclePhase{PhasePreBuild, PhaseOperations},
		},
		{
			name: "several sources claim several stages",
			src:  LifecycleSources{Manifests: true, InstalledTree: true, ContainerImage: true},
			want: []LifecyclePhase{PhasePreBuild, PhaseBuild, PhasePostBuild},
		},
		{
			name: "a pass that read nothing claims nothing",
			src:  LifecycleSources{},
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DerivePhases(tc.src)
			if len(got) != len(tc.want) {
				t.Fatalf("phases = %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Fatalf("phases = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// A re-scan writes the next revision of the same document. Copying the seed's
// version verbatim, as this used to, produced a hundred documents all claiming
// version 1 under one serialNumber, which no consumer can order.
func TestSeedCarryOverAdvancesTheRevision(t *testing.T) {
	seed := cyclonedx.NewDocument("1.7")
	seed.Version = 7
	seedSerial := seed.SerialNumber
	seed.Metadata.Tools = &Tools{Components: []Component{
		cyclonedx.VulnetixTool(cyclonedx.ToolSCA, "3.1.0"),
		{Type: "application", Name: "syft", Version: "1.2.3", Group: "Anchore"},
	}}

	bom := BuildFromLocalScan(nil, "1.7", &ScanContext{ToolName: cyclonedx.ToolSCA}, seed)

	if bom.SerialNumber != seedSerial {
		t.Errorf("serialNumber = %q, want the seed's %q", bom.SerialNumber, seedSerial)
	}
	if bom.Version != 8 {
		t.Errorf("version = %d, want 8", bom.Version)
	}

	tools := cyclonedx.ToolParticipants(bom)
	if len(tools) != 2 {
		t.Fatalf("tool entries = %d, want 2: %#v", len(tools), tools)
	}
	if tools[0].Name != cyclonedx.ToolSCA {
		t.Errorf("author = %q, want %q", tools[0].Name, cyclonedx.ToolSCA)
	}
	if tools[0].Version == "3.1.0" {
		t.Error("the seed's older self-identification survived; this run is the author")
	}
	if tools[1].Name != "syft" {
		t.Errorf("third-party tool not preserved: %#v", tools[1])
	}
}

// A tool entry that names no version is one a consumer cannot act on, and four
// builders used to default the version to the literal string "cli".
func TestAuthoringToolCarriesARealIdentity(t *testing.T) {
	tool := Authoring(cyclonedx.ToolSCA, nil).Tool
	switch {
	case tool.Version == "" || tool.Version == "cli":
		t.Errorf("tool version = %q", tool.Version)
	case tool.Group != cyclonedx.VulnetixToolGroup:
		t.Errorf("tool group = %q", tool.Group)
	case tool.Purl == "":
		t.Error("tool has no purl")
	case len(tool.ExternalReferences) == 0:
		t.Error("tool has no external references")
	}
}

func TestResolveAuthorshipPrecedence(t *testing.T) {
	overlay := Overlay{Path: "ov.json", BOM: &BOM{
		SerialNumber: "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
		Version:      4,
		Metadata: &Metadata{
			Manufacturer: &OrganizationalEntity{Name: "Overlay Manufacturer", URL: []string{"https://overlay.example"}},
			Authors:      []OrganizationalContact{{Name: "Overlay Author"}},
			Supplier:     &OrganizationalEntity{Name: "Overlay Supplier"},
			Lifecycles:   []Lifecycle{{Phase: "operations"}},
		},
	}}
	derived := []LifecyclePhase{PhasePreBuild}

	t.Run("overlay fills what nothing else states", func(t *testing.T) {
		a := ResolveAuthorship(cyclonedx.ToolCDX, AuthoringInputs{Overlays: []Overlay{overlay}}, derived)
		if a.Manufacturer == nil || a.Manufacturer.Name != "Overlay Manufacturer" {
			t.Errorf("manufacturer = %v", a.Manufacturer)
		}
		if len(a.Authors) != 1 || a.Authors[0].Name != "Overlay Author" {
			t.Errorf("authors = %v", a.Authors)
		}
		if a.Supplier == nil || a.Supplier.Name != "Overlay Supplier" {
			t.Errorf("supplier = %v", a.Supplier)
		}
		if a.SerialNumber != "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79" || a.BOMVersion != 4 {
			t.Errorf("serial/version = %s/%d", a.SerialNumber, a.BOMVersion)
		}
		if len(a.Phases) != 1 || a.Phases[0] != PhaseOperations {
			t.Errorf("phases = %v, want the overlay's", a.Phases)
		}
		if a.Tool.Name != cyclonedx.ToolCDX {
			t.Errorf("tool = %v", a.Tool)
		}
	})

	t.Run("flags and environment beat the overlay member by member", func(t *testing.T) {
		in := AuthoringInputs{
			Manufacturer:    ManufacturerSources{Env: "Env Ltd"},
			ManufacturerURL: "https://env.example",
			Authors:         []OrganizationalContact{{Name: "Flag Author", Email: "flag@example.com"}},
			SerialNumber:    "release-2026.11",
			BOMVersion:      7,
			Lifecycle:       []LifecyclePhase{PhaseBuild},
			Overlays:        []Overlay{overlay},
		}
		a := ResolveAuthorship(cyclonedx.ToolCDX, in, derived)
		if a.Manufacturer.Name != "Env Ltd" || len(a.Manufacturer.URL) != 1 || a.Manufacturer.URL[0] != "https://env.example" {
			t.Errorf("manufacturer = %+v", a.Manufacturer)
		}
		if a.Authors[0].Name != "Flag Author" {
			t.Errorf("authors = %v", a.Authors)
		}
		// Nothing above the overlay stated a supplier, so the overlay's stands.
		if a.Supplier == nil || a.Supplier.Name != "Overlay Supplier" {
			t.Errorf("supplier = %v", a.Supplier)
		}
		if a.SerialNumber != "release-2026.11" || a.BOMVersion != 7 {
			t.Errorf("serial/version = %s/%d", a.SerialNumber, a.BOMVersion)
		}
		if len(a.Phases) != 1 || a.Phases[0] != PhaseBuild {
			t.Errorf("phases = %v", a.Phases)
		}
	})

	t.Run("derived values are the floor", func(t *testing.T) {
		a := ResolveAuthorship(cyclonedx.ToolCDX, AuthoringInputs{}, derived)
		if a.Manufacturer != nil || a.Authors != nil || a.Supplier != nil || a.SerialNumber != "" || a.BOMVersion != 0 {
			t.Errorf("unstated members were invented: %+v", a)
		}
		if len(a.Phases) != 1 || a.Phases[0] != PhasePreBuild {
			t.Errorf("phases = %v, want derived", a.Phases)
		}
	})

	t.Run("a stated serial is applied deterministically", func(t *testing.T) {
		doc := cyclonedx.NewDocument("1.7")
		a := ResolveAuthorship(cyclonedx.ToolCDX, AuthoringInputs{SerialNumber: "release-2026.11", BOMVersion: 3}, nil)
		if _, err := cyclonedx.ApplyAuthorship(doc, a); err != nil {
			t.Fatal(err)
		}
		want := cyclonedx.NormalizeSerialNumber("release-2026.11")
		if doc.SerialNumber != want || !strings.HasPrefix(doc.SerialNumber, "urn:uuid:") || doc.Version != 3 {
			t.Errorf("serial/version = %s/%d, want %s/3", doc.SerialNumber, doc.Version, want)
		}
	})
}

func TestOrganizationDropsAnEmptyName(t *testing.T) {
	if Organization("  ", "https://x") != nil {
		t.Error("an empty name must leave the member absent")
	}
	e := Organization(" Acme ", "https://acme.example", "")
	if e.Name != "Acme" || len(e.URL) != 1 {
		t.Errorf("entity = %+v", e)
	}
}
