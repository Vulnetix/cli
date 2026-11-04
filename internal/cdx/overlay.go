package cdx

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ── Overlay files ────────────────────────────────────────────────────────────
//
// An overlay is a CycloneDX fragment the caller wants in the document: a
// supplier on the subject component, a service, a composition, an annotation,
// an analysis block on a vulnerability. The generator cannot know any of it, so
// the file says it and this merge puts it where CycloneDX defines it.
//
// The rules are the opposite of MergeBOMs, which protects what is already on
// disk: here the overlay wins for scalars, arrays are appended and
// de-duplicated, and a member this model does not interpret (services,
// compositions, annotations, formulation, declarations, definitions,
// externalReferences) replaces the whole member. Two things an overlay can
// never set: metadata.tools and metadata.timestamp, which are this run's own
// statement, and any vulnetix:* property, which is this product's vocabulary.

// LoadOverlay reads and checks one overlay file. Identity members in it
// (serialNumber, version, metadata.manufacturer, authors, supplier,
// lifecycles) are read by ResolveAuthorship; everything else by ApplyOverlay.
func LoadOverlay(path string) (Overlay, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Overlay{}, fmt.Errorf("overlay %s: %w", path, err)
	}
	var doc BOM
	if err := json.Unmarshal(data, &doc); err != nil {
		return Overlay{}, fmt.Errorf("overlay %s: not a JSON object: %w", path, err)
	}
	if doc.BOMFormat != "" && !strings.EqualFold(doc.BOMFormat, "CycloneDX") {
		return Overlay{}, fmt.Errorf("overlay %s: /bomFormat is %q, want CycloneDX", path, doc.BOMFormat)
	}
	if _, has := doc.Extra["signature"]; has {
		return Overlay{}, fmt.Errorf("overlay %s: /signature cannot be carried in: a signature covers the finished document, so sign the output instead (--sign)", path)
	}
	if p := reservedProperty(&doc); p != "" {
		return Overlay{}, fmt.Errorf("overlay %s: %s names a vulnetix: property, which only this product writes; use your own namespace", path, p)
	}
	return Overlay{Path: path, BOM: &doc}, nil
}

// reservedProperty returns the JSON pointer of the first vulnetix:* property in
// the overlay, or "".
func reservedProperty(doc *BOM) string {
	check := func(props []Property, base string) string {
		for i, p := range props {
			if strings.HasPrefix(p.Name, "vulnetix:") {
				return fmt.Sprintf("%s/%d/name", base, i)
			}
		}
		return ""
	}
	if p := check(doc.Properties, "/properties"); p != "" {
		return p
	}
	if doc.Metadata != nil {
		if p := check(doc.Metadata.Properties, "/metadata/properties"); p != "" {
			return p
		}
		if doc.Metadata.Component != nil {
			if p := check(doc.Metadata.Component.Properties, "/metadata/component/properties"); p != "" {
				return p
			}
		}
	}
	for i, c := range doc.Components {
		if p := check(c.Properties, fmt.Sprintf("/components/%d/properties", i)); p != "" {
			return p
		}
	}
	for i, v := range doc.Vulnerabilities {
		if p := check(v.Properties, fmt.Sprintf("/vulnerabilities/%d/properties", i)); p != "" {
			return p
		}
	}
	return ""
}

// ApplyOverlay merges one overlay into doc. The spec version must match: an
// overlay written for one version may carry members the other cannot.
func ApplyOverlay(doc *BOM, ov Overlay) error {
	if ov.BOM == nil {
		return nil
	}
	src := ov.BOM
	if src.SpecVersion != "" && doc.SpecVersion != "" && src.SpecVersion != doc.SpecVersion {
		return fmt.Errorf("overlay %s: /specVersion is %s but the document is %s; write the overlay for %s or pass --spec-version %s",
			ov.Path, src.SpecVersion, doc.SpecVersion, doc.SpecVersion, src.SpecVersion)
	}
	if doc.Metadata == nil {
		doc.Metadata = &Metadata{}
	}

	// Root members this model does not interpret replace the whole member.
	for k, v := range src.Extra {
		if doc.Extra == nil {
			doc.Extra = map[string]json.RawMessage{}
		}
		doc.Extra[k] = v
	}
	doc.Properties = upsertProperties(doc.Properties, src.Properties)

	if src.Metadata != nil {
		overlayMetadata(doc.Metadata, src.Metadata)
	}
	for _, c := range src.Components {
		idx := findComponentIndex(doc.Components, c)
		if idx < 0 {
			doc.Components = append(doc.Components, c)
			continue
		}
		overlayComponent(&doc.Components[idx], c)
	}
	mergeDependencies(doc, src.Dependencies)
	for _, v := range src.Vulnerabilities {
		idx := findVulnerabilityIndex(doc.Vulnerabilities, v)
		if idx < 0 {
			doc.Vulnerabilities = append(doc.Vulnerabilities, v)
			continue
		}
		overlayVulnerability(&doc.Vulnerabilities[idx], v)
	}
	return nil
}

// overlayMetadata applies the content members of an overlay's metadata. The
// identity members were consumed by ResolveAuthorship; tools and timestamp are
// this run's own and never come from a file.
func overlayMetadata(dst, src *Metadata) {
	if src.Component != nil {
		if dst.Component == nil {
			dst.Component = src.Component
		} else {
			overlayComponent(dst.Component, *src.Component)
		}
	}
	dst.Licenses = mergeLicenses(dst.Licenses, src.Licenses)
	dst.Properties = upsertProperties(dst.Properties, src.Properties)
	for k, v := range src.Extra {
		if dst.Extra == nil {
			dst.Extra = map[string]json.RawMessage{}
		}
		dst.Extra[k] = v
	}
}

// overlayComponent writes the overlay's members onto an existing component:
// scalars win when set, arrays append and de-duplicate, properties upsert.
// bom-ref is never changed, because the dependency graph refers to it.
func overlayComponent(dst *Component, src Component) {
	if src.Type != "" {
		dst.Type = src.Type
	}
	if src.Publisher != "" {
		dst.Publisher = src.Publisher
	}
	if src.Group != "" {
		dst.Group = src.Group
	}
	if src.Name != "" {
		dst.Name = src.Name
	}
	if src.Version != "" {
		dst.Version = src.Version
	}
	if src.Description != "" {
		dst.Description = src.Description
	}
	if src.Scope != "" {
		dst.Scope = src.Scope
	}
	if src.Purl != "" {
		dst.Purl = src.Purl
	}
	if src.Cpe != "" {
		dst.Cpe = src.Cpe
	}
	if src.Supplier != nil {
		dst.Supplier = src.Supplier
	}
	if src.Manufacturer != nil {
		dst.Manufacturer = src.Manufacturer
	}
	if src.ModelCard != nil {
		dst.ModelCard = src.ModelCard
	}
	if src.CryptoProperties != nil {
		dst.CryptoProperties = src.CryptoProperties
	}
	dst.Hashes = mergeHashes(dst.Hashes, src.Hashes)
	dst.Licenses = mergeLicenses(dst.Licenses, src.Licenses)
	dst.Authors = mergeContacts(dst.Authors, src.Authors)
	dst.ExternalReferences = mergeExternalRefs(dst.ExternalReferences, src.ExternalReferences)
	dst.Properties = upsertProperties(dst.Properties, src.Properties)
	for k, v := range src.Extra {
		if dst.Extra == nil {
			dst.Extra = map[string]json.RawMessage{}
		}
		dst.Extra[k] = v
	}
}

// findVulnerabilityIndex matches by id, and by bom-ref when the overlay gives
// one. An overlay rarely repeats the affects list, so vulnerabilityKey (which
// includes it) is too strict here.
func findVulnerabilityIndex(vulns []Vulnerability, target Vulnerability) int {
	for i, v := range vulns {
		if target.BOMRef != "" && v.BOMRef == target.BOMRef {
			return i
		}
		if target.ID != "" && v.ID == target.ID {
			return i
		}
	}
	return -1
}

// overlayVulnerability is how an overlay states an analysis: the overlay's
// analysis block replaces the existing one, and its other members fill gaps.
func overlayVulnerability(dst *Vulnerability, src Vulnerability) {
	if src.Analysis != nil {
		dst.Analysis = src.Analysis
	}
	if src.Description != "" {
		dst.Description = src.Description
	}
	if src.Recommendation != "" {
		dst.Recommendation = src.Recommendation
	}
	if src.Source != nil {
		dst.Source = src.Source
	}
	if len(src.Ratings) > 0 {
		dst.Ratings = append(dst.Ratings, src.Ratings...)
	}
	seen := map[string]bool{}
	for _, a := range dst.Affects {
		seen[a.Ref] = true
	}
	for _, a := range src.Affects {
		if !seen[a.Ref] {
			seen[a.Ref] = true
			dst.Affects = append(dst.Affects, a)
		}
	}
	dst.Properties = upsertProperties(dst.Properties, src.Properties)
	for k, v := range src.Extra {
		if dst.Extra == nil {
			dst.Extra = map[string]json.RawMessage{}
		}
		dst.Extra[k] = v
	}
}

// upsertProperties sets each incoming property by name, so a name appears once
// and the overlay's value wins. It is the library's upsert applied in bulk.
func upsertProperties(existing, incoming []Property) []Property {
	for _, p := range incoming {
		existing = cycloneSetProperty(existing, p.Name, p.Value)
	}
	return existing
}
