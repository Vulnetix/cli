package bom

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/vulnetix/cli/v3/internal/cdx"
	"github.com/vulnetix/cli/v3/internal/license"
	"github.com/vulnetix/cli/v3/internal/purl"
)

// spdxNoAssertion is the SPDX spelling for "no claim is made".
//
// It is a value, not an absence: a package whose licenseConcluded is
// NOASSERTION has been examined and found undeterminable, which is different
// from a field that was never written. Both end up as no license on the
// CycloneDX side, but only the latter is a document-quality defect, and
// quality.go needs to be able to tell them apart.
const spdxNoAssertion = "NOASSERTION"

// spdxNone is the SPDX spelling for "there is definitively no license".
const spdxNone = "NONE"

// parseSPDX converts an SPDX 2.x JSON document into the canonical CycloneDX model.
//
// The mapping is deliberately conservative: an SPDX package becomes a
// CycloneDX component, its purl external reference becomes the component purl
// (and its bom-ref, matching the write side), and DEPENDS_ON / CONTAINS
// relationships become dependency-graph edges. Anything SPDX expresses that
// CycloneDX has no home for is preserved as a namespaced property rather than
// dropped, so `bom import x.spdx.json --out x.cdx.json` loses no information a
// later pass could have used.
func parseSPDX(data []byte) (*cdx.BOM, error) {
	var doc license.SPDXDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing SPDX: %w", err)
	}

	bom := &cdx.BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: cdx.ValidSpecVersions()[0],
		Version:     1,
		Metadata: &cdx.Metadata{
			Timestamp: doc.CreationInfo.Created,
		},
	}
	// An SPDX documentNamespace is a URI unique to the document, which is
	// exactly what a CycloneDX serialNumber is for.
	if doc.DocumentNamespace != "" {
		bom.SerialNumber = doc.DocumentNamespace
	}
	if tools := spdxTools(doc.CreationInfo.Creators); len(tools) > 0 {
		bom.Metadata.Tools = &cdx.Tools{Components: tools}
	}
	if authors := spdxAuthors(doc.CreationInfo.Creators); len(authors) > 0 {
		bom.Metadata.Authors = authors
	}

	// spdxID → index into bom.Components, so relationships can be resolved to
	// bom-refs in a second pass.
	refByID := make(map[string]string, len(doc.Packages))

	for i := range doc.Packages {
		comp := spdxPackageToComponent(&doc.Packages[i])
		refByID[doc.Packages[i].SPDXID] = comp.BOMRef
		bom.Components = append(bom.Components, comp)
	}

	rootID := spdxRootID(&doc)
	if rootID != "" {
		if idx := indexOfRef(bom.Components, refByID[rootID]); idx >= 0 {
			root := bom.Components[idx]
			// The document's subject belongs in metadata.component, not in the
			// component list beside its own dependencies.
			bom.Components = append(bom.Components[:idx], bom.Components[idx+1:]...)
			bom.Metadata.Component = &root
		}
	}
	if bom.Metadata.Component == nil && doc.Name != "" {
		bom.Metadata.Component = &cdx.Component{
			Type:   "application",
			Name:   doc.Name,
			BOMRef: "SPDXRef-DOCUMENT",
		}
		refByID["SPDXRef-DOCUMENT"] = "SPDXRef-DOCUMENT"
	}

	bom.Dependencies = spdxDependencies(doc.Relationships, refByID)
	return bom, nil
}

// spdxPackageToComponent maps one SPDX package onto a CycloneDX component.
func spdxPackageToComponent(p *license.SPDXPackage) cdx.Component {
	comp := cdx.Component{
		Type:        spdxComponentType(p.PrimaryPackagePurpose),
		Name:        p.Name,
		Version:     p.VersionInfo,
		Description: firstNonEmpty(p.Summary, p.Description),
	}

	// purl, when the package carries one, is the identity that matters
	// everywhere downstream — matching, diffing, VDB lookup — so it is also
	// the bom-ref, the same rule the CycloneDX writer follows.
	if pu := spdxPurl(p.ExternalRefs); pu != "" {
		comp.Purl = pu
		comp.BOMRef = pu
		// A purl's type is the authority on ecosystem; recording it saves every
		// consumer from re-parsing the purl.
		if parsed, err := purl.Parse(pu); err == nil {
			if eco, ok := purl.EcosystemForType(parsed.Type); ok {
				comp.Properties = append(comp.Properties, cdx.Property{
					Name: "vulnetix:sbom/ecosystem", Value: eco,
				})
			}
		}
	} else {
		comp.BOMRef = p.SPDXID
	}

	comp.Licenses = spdxLicenses(p.LicenseConcluded, p.LicenseDeclared)

	for _, ck := range p.Checksums {
		if alg := spdxHashAlg(ck.Algorithm); alg != "" && ck.ChecksumValue != "" {
			comp.Hashes = append(comp.Hashes, cdx.Hash{Alg: alg, Content: ck.ChecksumValue})
		}
	}

	if p.Homepage != "" && p.Homepage != spdxNoAssertion {
		comp.ExternalReferences = append(comp.ExternalReferences, cdx.ExternalReference{
			Type: "website", URL: p.Homepage,
		})
	}
	if p.DownloadLocation != "" && p.DownloadLocation != spdxNoAssertion && p.DownloadLocation != spdxNone {
		comp.ExternalReferences = append(comp.ExternalReferences, cdx.ExternalReference{
			Type: "distribution", URL: p.DownloadLocation,
		})
	}

	// Supplier and originator are free-form SPDX strings ("Organization: Acme
	// (x@acme.io)"), not the structured object CycloneDX wants; carrying them
	// verbatim as properties keeps the information without asserting a
	// structure the source never had.
	addProp := func(name, value string) {
		if value != "" && value != spdxNoAssertion {
			comp.Properties = append(comp.Properties, cdx.Property{Name: name, Value: value})
		}
	}
	addProp("vulnetix:spdx/supplier", p.Supplier)
	addProp("vulnetix:spdx/originator", p.Originator)
	addProp("vulnetix:spdx/source-info", p.SourceInfo)
	addProp("vulnetix:spdx/package-file-name", p.PackageFileName)
	addProp("vulnetix:spdx/spdxid", p.SPDXID)

	return comp
}

// spdxComponentType maps primaryPackagePurpose onto a CycloneDX component type.
//
// SPDX 2.3's purpose vocabulary is broader than CycloneDX's type enum, and an
// unrecognised value must not become an invalid type — "library" is the safe
// default because that is what the overwhelming majority of SBOM packages are.
func spdxComponentType(purpose string) string {
	switch strings.ToUpper(purpose) {
	case "APPLICATION", "INSTALL":
		return "application"
	case "FRAMEWORK":
		return "framework"
	case "CONTAINER":
		return "container"
	case "OPERATING_SYSTEM", "OPERATING-SYSTEM":
		return "operating-system"
	case "DEVICE":
		return "device"
	case "FIRMWARE":
		return "firmware"
	case "FILE":
		return "file"
	default:
		return "library"
	}
}

// spdxPurl extracts the package's purl from its external references.
func spdxPurl(refs []license.SPDXExternalRef) string {
	for _, r := range refs {
		if strings.EqualFold(r.ReferenceType, "purl") {
			return r.ReferenceLocator
		}
	}
	return ""
}

// spdxLicenses converts SPDX license fields into CycloneDX licence entries.
//
// licenseConcluded is preferred over licenseDeclared: declared is what the
// package claims about itself, concluded is what the SBOM producer determined
// after looking, and the latter is the more considered answer. A compound
// expression stays an expression — splitting "MIT OR Apache-2.0" into two
// licence entries would assert the package is under both, which is the
// opposite of what it says.
func spdxLicenses(concluded, declared string) []cdx.LicenseChoice {
	pick := concluded
	if !usableSPDXLicense(pick) {
		pick = declared
	}
	if !usableSPDXLicense(pick) {
		return nil
	}
	if isCompoundExpression(pick) {
		return []cdx.LicenseChoice{{Expression: pick}}
	}
	if canonical := license.CanonicalSPDXID(pick); canonical != "" {
		return []cdx.LicenseChoice{{License: &cdx.LicenseData{ID: canonical}}}
	}
	// Not a recognised SPDX identifier — it must travel as a free-form name,
	// because license.id is schema-constrained to the SPDX enum and an
	// unrecognised value there fails validation.
	return []cdx.LicenseChoice{{License: &cdx.LicenseData{Name: pick}}}
}

// usableSPDXLicense reports whether a licence field carries an actual claim.
func usableSPDXLicense(s string) bool {
	s = strings.TrimSpace(s)
	return s != "" && s != spdxNoAssertion && s != spdxNone
}

// isCompoundExpression reports whether an SPDX licence string is an expression
// rather than a bare identifier.
func isCompoundExpression(s string) bool {
	for _, tok := range strings.Fields(s) {
		switch strings.ToUpper(tok) {
		case "OR", "AND", "WITH":
			return true
		}
	}
	return strings.ContainsAny(s, "()")
}

// spdxHashAlg maps an SPDX checksum algorithm onto its CycloneDX spelling.
//
// Only algorithms both specs name are mapped; an unmapped algorithm returns ""
// and the checksum is dropped rather than emitted under a value the CycloneDX
// schema would reject.
func spdxHashAlg(alg string) string {
	switch strings.ToUpper(strings.ReplaceAll(alg, "-", "")) {
	case "MD5":
		return "MD5"
	case "SHA1":
		return "SHA-1"
	case "SHA256":
		return "SHA-256"
	case "SHA384":
		return "SHA-384"
	case "SHA512":
		return "SHA-512"
	case "SHA3256":
		return "SHA3-256"
	case "SHA3384":
		return "SHA3-384"
	case "SHA3512":
		return "SHA3-512"
	case "BLAKE2B256":
		return "BLAKE2b-256"
	case "BLAKE2B384":
		return "BLAKE2b-384"
	case "BLAKE2B512":
		return "BLAKE2b-512"
	case "BLAKE3":
		return "BLAKE3"
	default:
		return ""
	}
}

// spdxRootID finds the SPDX id of the package the document describes.
func spdxRootID(doc *license.SPDXDocument) string {
	for _, id := range doc.DocumentDescribes {
		if id != "" && id != "SPDXRef-DOCUMENT" {
			return id
		}
	}
	for _, rel := range doc.Relationships {
		if strings.EqualFold(rel.RelType, "DESCRIBES") && rel.Element == "SPDXRef-DOCUMENT" {
			return rel.RelatedElement
		}
		if strings.EqualFold(rel.RelType, "DESCRIBED_BY") && rel.RelatedElement == "SPDXRef-DOCUMENT" {
			return rel.Element
		}
	}
	return ""
}

// spdxDependencies converts SPDX relationships into a CycloneDX dependency graph.
//
// Only the relationship types that express containment are translated.
// DEPENDENCY_OF and CONTAINED_BY are the inverses of DEPENDS_ON and CONTAINS
// and are flipped rather than ignored — Syft emits the inverse forms, and
// dropping them would produce an empty graph for a document that fully
// describes one.
func spdxDependencies(rels []license.SPDXRelationship, refByID map[string]string) []cdx.CDXDependency {
	edges := make(map[string]map[string]bool)
	add := func(fromID, toID string) {
		from, okFrom := refByID[fromID]
		to, okTo := refByID[toID]
		if !okFrom || !okTo || from == "" || to == "" || from == to {
			return
		}
		if edges[from] == nil {
			edges[from] = make(map[string]bool)
		}
		edges[from][to] = true
	}

	for _, rel := range rels {
		switch strings.ToUpper(rel.RelType) {
		case "DEPENDS_ON", "CONTAINS", "BUILD_DEPENDENCY_OF_INVERSE":
			add(rel.Element, rel.RelatedElement)
		case "DEPENDENCY_OF", "CONTAINED_BY", "DEV_DEPENDENCY_OF", "OPTIONAL_DEPENDENCY_OF",
			"RUNTIME_DEPENDENCY_OF", "BUILD_DEPENDENCY_OF", "PREREQUISITE_FOR":
			add(rel.RelatedElement, rel.Element)
		}
	}

	out := make([]cdx.CDXDependency, 0, len(edges))
	for ref, targets := range edges {
		dependsOn := make([]string, 0, len(targets))
		for t := range targets {
			dependsOn = append(dependsOn, t)
		}
		sort.Strings(dependsOn)
		out = append(out, cdx.CDXDependency{Ref: ref, DependsOn: dependsOn})
	}
	// Deterministic ordering: a diff of two generated SBOMs should show real
	// changes, not map iteration order.
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out
}

// spdxTools extracts tool creators as CycloneDX tool components.
func spdxTools(creators []string) []cdx.Component {
	var out []cdx.Component
	for _, c := range creators {
		rest, ok := strings.CutPrefix(c, "Tool:")
		if !ok {
			continue
		}
		name, version := splitToolVersion(strings.TrimSpace(rest))
		if name == "" {
			continue
		}
		out = append(out, cdx.Component{Type: "application", Name: name, Version: version})
	}
	return out
}

// splitToolVersion splits an SPDX tool creator string into name and version.
//
// The spec suggests "name-version" but writers also emit "name version" and
// bare names, so both separators are tried and a bare name is valid.
func splitToolVersion(s string) (name, version string) {
	if idx := strings.LastIndex(s, " "); idx > 0 {
		return s[:idx], s[idx+1:]
	}
	if idx := strings.LastIndex(s, "-"); idx > 0 {
		return s[:idx], s[idx+1:]
	}
	return s, ""
}

// spdxAuthors extracts Person and Organization creators as CycloneDX authors.
func spdxAuthors(creators []string) []cdx.OrganizationalContact {
	var out []cdx.OrganizationalContact
	for _, c := range creators {
		var value string
		switch {
		case strings.HasPrefix(c, "Person:"):
			value = strings.TrimSpace(strings.TrimPrefix(c, "Person:"))
		case strings.HasPrefix(c, "Organization:"):
			value = strings.TrimSpace(strings.TrimPrefix(c, "Organization:"))
		default:
			continue
		}
		if value == "" || value == spdxNoAssertion {
			continue
		}
		name, email := splitNameEmail(value)
		out = append(out, cdx.OrganizationalContact{Name: name, Email: email})
	}
	return out
}

// splitNameEmail pulls a parenthesised email out of an SPDX creator string.
func splitNameEmail(s string) (name, email string) {
	open := strings.LastIndex(s, "(")
	if open < 0 || !strings.HasSuffix(s, ")") {
		return s, ""
	}
	inner := s[open+1 : len(s)-1]
	if !strings.Contains(inner, "@") {
		return s, ""
	}
	return strings.TrimSpace(s[:open]), inner
}

// indexOfRef returns the position of the component with the given bom-ref, or -1.
func indexOfRef(comps []cdx.Component, ref string) int {
	if ref == "" {
		return -1
	}
	for i := range comps {
		if comps[i].BOMRef == ref {
			return i
		}
	}
	return -1
}

// firstNonEmpty returns the first non-empty argument.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" && v != spdxNoAssertion {
			return v
		}
	}
	return ""
}
