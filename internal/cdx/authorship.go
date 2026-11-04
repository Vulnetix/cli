package cdx

import (
	"errors"
	"fmt"
	"strings"

	cyclonedx "github.com/Vulnetix/vdb-cyclonedx"
	"github.com/vulnetix/cli/v4/internal/buildinfo"
	"github.com/vulnetix/cli/v4/internal/gitctx"
)

// ── The two judgement calls this CLI owns ────────────────────────────────────
//
// vdb-cyclonedx knows what CycloneDX allows a document to say about its own
// authorship and at which spec versions. It cannot know the two things that are
// specific to a run: which organization is running it, and which stage of the
// lifecycle the data was captured at. Those are decided here, once, and passed
// to the library.

// Authorship, LifecyclePhase and the phase constants are re-exported so callers
// in this repository work in one vocabulary rather than importing the library
// alongside this package for a single enum.
type (
	Authorship     = cyclonedx.Authorship
	LifecyclePhase = cyclonedx.LifecyclePhase
)

const (
	PhaseDesign       = cyclonedx.PhaseDesign
	PhasePreBuild     = cyclonedx.PhasePreBuild
	PhaseBuild        = cyclonedx.PhaseBuild
	PhasePostBuild    = cyclonedx.PhasePostBuild
	PhaseOperations   = cyclonedx.PhaseOperations
	PhaseDiscovery    = cyclonedx.PhaseDiscovery
	PhaseDecommission = cyclonedx.PhaseDecommission
)

// ManufacturerSources are the places a run can learn which organization it is
// running on behalf of, most direct first.
type ManufacturerSources struct {
	// Override is an explicit --bom-manufacturer value.
	Override string
	// Env is VULNETIX_BOM_MANUFACTURER.
	Env string
	// CIOwner is the repository owner the CI provider states. Populated for
	// GitHub, GitLab, Azure DevOps, Bitbucket and Jenkins by internal/config.
	CIOwner string
	// Git is the repository itself, used when nothing above answered.
	Git *gitctx.GitContext
	// OrgID is the Vulnetix organisation this run authenticated as. It names the
	// document's manufacturer by identifier when no human-readable name resolves
	// well enough to print, and rides along as bom-ref when one does.
	OrgID string
}

// ResolveManufacturer answers "which organization created this BOM".
//
// CycloneDX is explicit that metadata.manufacturer is "the organization that
// created the BOM", and that it is the field to use for documents produced by
// automated processes. For a scan that means the organization running the scan,
// not the vendor of the scanner — the scanner is named in metadata.tools. A
// document claiming Vulnetix created an inventory of somebody else's repository
// says something different, and something untrue.
//
// It returns nil rather than guessing. An absent manufacturer is honest and
// costs a consumer one unknown; a wrong one is a false statement they have no
// way to detect.
func ResolveManufacturer(src ManufacturerSources) *OrganizationalEntity {
	name := firstNonBlank(src.Override, src.Env, src.CIOwner)
	var repoURL string
	if src.Git != nil && len(src.Git.RemoteURLs) > 0 {
		repoURL = normalizeVCSURL(src.Git.RemoteURLs[0])
		if name == "" {
			if owner, _, found := strings.Cut(extractRepoName(src.Git.RemoteURLs[0]), "/"); found {
				name = owner
			}
		}
	}
	if name == "" {
		return nil
	}

	entity := &OrganizationalEntity{Name: name}
	if src.OrgID != "" {
		// The org id ties the document to a Vulnetix organisation without
		// asserting a display name the CLI cannot resolve; bom-ref is the member
		// CycloneDX provides for exactly that kind of stable handle.
		entity.BOMRef = "urn:uuid:" + src.OrgID
	}
	if repoURL != "" {
		if owner := ownerURLFrom(repoURL); owner != "" {
			entity.URL = []string{owner}
		}
	}
	return entity
}

// ownerURLFrom trims a repository URL back to the owner it belongs to, which is
// the page a reader would land on to identify the organization.
func ownerURLFrom(repoURL string) string {
	trimmed := strings.TrimSuffix(repoURL, "/")
	if idx := strings.LastIndexByte(trimmed, '/'); idx > len("https://") {
		return trimmed[:idx]
	}
	return ""
}

func firstNonBlank(values ...string) string {
	for _, v := range values {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// LifecycleSources describes what a pass actually read, which is what decides
// the phases it may claim.
type LifecycleSources struct {
	// Manifests is true when declared dependencies were read from manifests or
	// lockfiles.
	Manifests bool
	// InstalledTree is true when a resolved, installed dependency tree was
	// walked — node_modules, site-packages, vendor/ and the like.
	InstalledTree bool
	// ContainerImage is true when a built image or its package databases were
	// read, and CompiledArtifacts when package metadata was recovered out of
	// compiled binaries.
	ContainerImage    bool
	CompiledArtifacts bool
	// Discovery is true for a pass that identifies assets by observation rather
	// than by resolving a declared set — the AI and crypto inventories.
	Discovery bool
	// Deployed is true when the run was given deployment context, which is a
	// statement that this inventory describes something running.
	Deployed bool
}

// DerivePhases maps what a pass read to the lifecycle phases it may claim.
//
// CycloneDX defines lifecycles as "the stage(s) in which data in the BOM was
// captured", and it is an array precisely because one pass can read several
// kinds of source. Every builder used to hardcode `build`, which is wrong for
// the most common case of all: reading a manifest tells you what a build is
// *intended* to resolve, and the artefacts do not exist yet. That is pre-build.
//
// An empty result means the pass cannot honestly claim any stage, and the
// document says nothing rather than something convenient.
func DerivePhases(src LifecycleSources) []LifecyclePhase {
	var phases []LifecyclePhase
	if src.Manifests {
		phases = append(phases, PhasePreBuild)
	}
	if src.InstalledTree {
		phases = append(phases, PhaseBuild)
	}
	if src.ContainerImage || src.CompiledArtifacts {
		phases = append(phases, PhasePostBuild)
	}
	if src.Discovery {
		phases = append(phases, PhaseDiscovery)
	}
	if src.Deployed {
		phases = append(phases, PhaseOperations)
	}
	return phases
}

// ToolVersion is the version every metadata.tools entry this CLI writes carries.
func ToolVersion() string { return buildinfo.Version }

// Authoring builds the Authorship for a document this CLI creates. It is the
// only place in this repository that assembles a tool entry.
func Authoring(toolName string, manufacturer *OrganizationalEntity, phases ...LifecyclePhase) Authorship {
	return Authorship{
		Manufacturer: manufacturer,
		Tool:         cyclonedx.VulnetixTool(toolName, ToolVersion()),
		Phases:       phases,
	}
}

// Participating returns the tool component this CLI appends to a document it is
// transforming but did not author.
func Participating(toolName string) Component {
	return cyclonedx.VulnetixTool(toolName, ToolVersion())
}

// toolComponents reads a tool table that may be absent, so callers merging two
// documents do not each repeat the nil checks.
func toolComponents(t *Tools) []Component {
	if t == nil {
		return nil
	}
	return t.Components
}

// ParseLifecyclePhases parses a comma-separated phase list, as --lifecycle
// supplies. An unrecognised phase is an error rather than a custom-phase
// fallback, because a typo silently becoming a custom lifecycle name is
// indistinguishable downstream from a deliberate one.
func ParseLifecyclePhases(csv string) ([]LifecyclePhase, error) {
	return cyclonedx.ParseLifecyclePhases(csv)
}

// ── What a run may say about its own document ────────────────────────────────
//
// Everything below turns the caller's stated intent (flags, environment, an
// overlay file) into the one Authorship the library applies. Precedence is
// flag > environment > overlay > derived, and it holds member by member: a
// supplier from an overlay survives an explicit --bom-author, because the two
// say different things.

// ComponentOverride replaces the git-derived members of metadata.component. A
// zero field keeps the derived value.
type ComponentOverride struct {
	Name, Version, Type, Group, Purl string
}

// Overlay is a CycloneDX fragment the caller asked to merge into the document,
// kept with the path it came from so a violation can name the file.
type Overlay struct {
	Path string
	BOM  *BOM
}

// AuthoringInputs is everything the caller stated about the document's
// identity and content, before any of it has been resolved. The command layer
// fills it from flags and environment; this package decides what it means.
type AuthoringInputs struct {
	// Manufacturer gathers the candidates for metadata.manufacturer (the
	// explicit flag, the environment, the CI owner, git). The git fallback is
	// filled in where git context is already collected.
	Manufacturer ManufacturerSources
	// ManufacturerURL replaces the owner URL derived from the git remote.
	ManufacturerURL string
	// Authors become metadata.authors.
	Authors []OrganizationalContact
	// SupplierName and SupplierURL become metadata.supplier.
	SupplierName, SupplierURL string
	// SerialNumber is normalised to a urn:uuid; "" keeps a derived or minted one.
	SerialNumber string
	// BOMVersion is the document's version member; 0 keeps the derived one.
	BOMVersion int
	// Lifecycle replaces the phases the pass would derive. Nil means derive.
	Lifecycle []LifecyclePhase
	// Licenses are the licences of the document itself (metadata.licenses).
	Licenses []LicenseChoice
	// Properties are upserted into metadata.properties.
	Properties []Property
	// Component overrides the derived subject component.
	Component ComponentOverride
	// Overlays are applied in order; a later overlay wins over an earlier one.
	Overlays []Overlay
}

// Organization builds an organizational entity from a name and optional URL.
// It returns nil for an empty name, so an unset flag leaves the member absent.
func Organization(name string, url ...string) *OrganizationalEntity {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil
	}
	e := &OrganizationalEntity{Name: name}
	for _, u := range url {
		if u = strings.TrimSpace(u); u != "" {
			e.URL = append(e.URL, u)
		}
	}
	return e
}

// ResolveAuthorship answers every identity question for a document this CLI
// authors, in one place. derivedPhases are the stages the pass can claim from
// what it read; they are used only when neither a flag nor an overlay states
// the phases.
func ResolveAuthorship(toolName string, in AuthoringInputs, derivedPhases []LifecyclePhase) Authorship {
	ov := lastOverlay(in.Overlays)
	var ovMeta *Metadata
	if ov != nil {
		ovMeta = ov.Metadata
	}

	phases := in.Lifecycle
	if phases == nil && ovMeta != nil {
		for _, l := range ovMeta.Lifecycles {
			if p := LifecyclePhase(l.Phase); p != "" && p.Valid() {
				phases = append(phases, p)
			}
		}
	}
	if phases == nil {
		phases = derivedPhases
	}

	a := Authoring(toolName, ResolveManufacturer(in.Manufacturer), phases...)
	if a.Manufacturer == nil && ovMeta != nil && ovMeta.Manufacturer != nil {
		a.Manufacturer = ovMeta.Manufacturer
	}
	if a.Manufacturer != nil && strings.TrimSpace(in.ManufacturerURL) != "" {
		a.Manufacturer.URL = []string{strings.TrimSpace(in.ManufacturerURL)}
	}

	a.Authors = in.Authors
	if len(a.Authors) == 0 && ovMeta != nil {
		a.Authors = ovMeta.Authors
	}

	a.Supplier = Organization(in.SupplierName, in.SupplierURL)
	if a.Supplier == nil && ovMeta != nil {
		a.Supplier = ovMeta.Supplier
	}

	a.SerialNumber = strings.TrimSpace(in.SerialNumber)
	if a.SerialNumber == "" && ov != nil {
		a.SerialNumber = ov.SerialNumber
	}
	a.BOMVersion = in.BOMVersion
	if a.BOMVersion == 0 && ov != nil {
		a.BOMVersion = ov.Version
	}
	return a
}

func lastOverlay(overlays []Overlay) *BOM {
	for i := len(overlays) - 1; i >= 0; i-- {
		if overlays[i].BOM != nil {
			return overlays[i].BOM
		}
	}
	return nil
}

// ApplyDocumentOverrides applies, after the builder has produced the document
// and before it is marshalled, everything the caller stated about its content:
// the overlays in order, then the document licences, then the properties, then
// the subject component. Flags come last so they win over an overlay. Identity
// members (serial, version, manufacturer, authors, supplier, lifecycles) are
// not touched here; ResolveAuthorship consumed them.
func ApplyDocumentOverrides(doc *BOM, in AuthoringInputs) error {
	if doc == nil {
		return errors.New("authorship: nil document")
	}
	if doc.Metadata == nil {
		doc.Metadata = &Metadata{}
	}
	for _, ov := range in.Overlays {
		if err := ApplyOverlay(doc, ov); err != nil {
			return err
		}
	}
	doc.Metadata.Licenses = mergeLicenses(doc.Metadata.Licenses, in.Licenses)
	for _, p := range in.Properties {
		doc.Metadata.SetProperty(p.Name, p.Value)
	}
	applyComponentOverride(doc, in.Component)
	return nil
}

func applyComponentOverride(doc *BOM, o ComponentOverride) {
	if o == (ComponentOverride{}) {
		return
	}
	if doc.Metadata.Component == nil {
		doc.Metadata.Component = &Component{Type: "application", BOMRef: "urn:project", Name: "project"}
	}
	c := doc.Metadata.Component
	if o.Name != "" {
		c.Name = o.Name
	}
	if o.Version != "" {
		c.Version = o.Version
	}
	if o.Type != "" {
		c.Type = o.Type
	}
	if o.Group != "" {
		c.Group = o.Group
	}
	if o.Purl != "" {
		c.Purl = o.Purl
	}
}

// Reauthor stamps a document that is being rewritten at the path it was read
// from: the serial is kept, the version increments, and this run's identity is
// applied when this product authored the original. A third-party author keeps
// its claim and this run is appended to metadata.tools. See ReviseInPlace.
func Reauthor(doc *BOM, a Authorship) error {
	_, err := cyclonedx.ReviseInPlace(doc, a)
	return err
}

// DocumentOf unwraps the value a Build*Document function returns.
func DocumentOf(v any) (*BOM, error) {
	doc, ok := v.(*BOM)
	if !ok || doc == nil {
		return nil, fmt.Errorf("cyclonedx: builder returned %T, want *Document", v)
	}
	return doc, nil
}

// ComponentTypes is the CycloneDX component classification enum, the values
// --component-type accepts.
var ComponentTypes = []string{
	"application", "framework", "library", "container", "platform",
	"operating-system", "device", "device-driver", "firmware", "file",
	"machine-learning-model", "data", "cryptographic-asset",
}

// ValidComponentType reports whether t is a CycloneDX component classification.
func ValidComponentType(t string) bool {
	for _, v := range ComponentTypes {
		if v == t {
			return true
		}
	}
	return false
}
