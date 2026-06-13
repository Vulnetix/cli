package cdx

// MergeUpstream merges a server-returned CycloneDX 1.6 document (from the
// /v2/cli.sca envelope) into a locally-built BOM. The merge is purl-keyed:
//   - components present locally but missing upstream are kept verbatim
//   - components present upstream are matched against local by purl (then
//     by `bom-ref`, then by name@version) and any new fields (group, etc.)
//     are filled in without overwriting locally-detected values
//   - all upstream vulnerabilities are appended; their `affects[].ref` is
//     rewritten to point at the local bom-ref so downstream tooling can
//     traverse the local component graph
//
// The merge is non-destructive: local data wins on field conflicts, upstream
// fills gaps. Callers that need a server-authoritative merge (e.g. the
// reverse direction) should not use this helper.

import (
	"encoding/json"
	"fmt"
	"strings"
)

// MergeBOMs merges two locally-built CycloneDX documents. It is designed for
// the shared .vulnetix/sbom.cdx.json file where SCA and container scans both
// write component inventory. Existing data is preserved, incoming data fills
// gaps and adds new components, tools, vulnerabilities, and dependencies.
func MergeBOMs(existing, incoming *BOM) *BOM {
	if existing == nil {
		return incoming
	}
	if incoming == nil {
		return existing
	}

	if existing.BOMFormat == "" {
		existing.BOMFormat = incoming.BOMFormat
	}
	if existing.SpecVersion == "" {
		existing.SpecVersion = incoming.SpecVersion
	}
	if existing.SerialNumber == "" {
		existing.SerialNumber = incoming.SerialNumber
	}
	if existing.Version == 0 {
		existing.Version = incoming.Version
	}
	mergeMetadata(existing, incoming)
	mergeComponents(existing, incoming.Components)
	mergeVulnerabilities(existing, incoming.Vulnerabilities)
	mergeDependencies(existing, incoming.Dependencies)
	return existing
}

func mergeMetadata(existing, incoming *BOM) {
	if incoming.Metadata == nil {
		return
	}
	if existing.Metadata == nil {
		existing.Metadata = incoming.Metadata
		return
	}
	if incoming.Metadata.Timestamp != "" {
		existing.Metadata.Timestamp = incoming.Metadata.Timestamp
	}
	if len(existing.Metadata.Lifecycles) == 0 {
		existing.Metadata.Lifecycles = incoming.Metadata.Lifecycles
	}
	if existing.Metadata.Component == nil {
		existing.Metadata.Component = incoming.Metadata.Component
	}
	if len(existing.Metadata.Authors) == 0 {
		existing.Metadata.Authors = incoming.Metadata.Authors
	}
	existing.Metadata.Properties = mergeProperties(existing.Metadata.Properties, incoming.Metadata.Properties)

	if incoming.Metadata.Tools == nil {
		return
	}
	if existing.Metadata.Tools == nil {
		existing.Metadata.Tools = incoming.Metadata.Tools
		return
	}
	for _, tool := range incoming.Metadata.Tools.Components {
		if findComponentIndex(existing.Metadata.Tools.Components, tool) < 0 {
			existing.Metadata.Tools.Components = append(existing.Metadata.Tools.Components, tool)
		}
	}
}

func mergeComponents(bom *BOM, incoming []Component) {
	for _, comp := range incoming {
		idx := findComponentIndex(bom.Components, comp)
		if idx < 0 {
			bom.Components = append(bom.Components, comp)
			continue
		}
		mergeComponentGaps(&bom.Components[idx], comp)
	}
}

func findComponentIndex(components []Component, target Component) int {
	for i, comp := range components {
		switch {
		case target.Purl != "" && comp.Purl == target.Purl:
			return i
		case target.BOMRef != "" && comp.BOMRef == target.BOMRef:
			return i
		case target.Name != "" && comp.Name == target.Name && comp.Version == target.Version && comp.Type == target.Type:
			return i
		}
	}
	return -1
}

func mergeComponentGaps(existing *Component, incoming Component) {
	if existing.Type == "" {
		existing.Type = incoming.Type
	}
	if existing.BOMRef == "" {
		existing.BOMRef = incoming.BOMRef
	}
	if existing.Name == "" {
		existing.Name = incoming.Name
	}
	if existing.Version == "" {
		existing.Version = incoming.Version
	}
	if existing.Description == "" {
		existing.Description = incoming.Description
	}
	if existing.Scope == "" {
		existing.Scope = incoming.Scope
	}
	if existing.Purl == "" {
		existing.Purl = incoming.Purl
	}
	existing.Hashes = mergeHashes(existing.Hashes, incoming.Hashes)
	existing.Licenses = mergeLicenses(existing.Licenses, incoming.Licenses)
	existing.Authors = mergeContacts(existing.Authors, incoming.Authors)
	existing.ExternalReferences = mergeExternalRefs(existing.ExternalReferences, incoming.ExternalReferences)
	existing.Properties = mergeProperties(existing.Properties, incoming.Properties)
}

func mergeVulnerabilities(bom *BOM, incoming []Vulnerability) {
	seen := map[string]bool{}
	for _, v := range bom.Vulnerabilities {
		seen[vulnerabilityKey(v)] = true
	}
	for _, v := range incoming {
		key := vulnerabilityKey(v)
		if seen[key] {
			continue
		}
		seen[key] = true
		bom.Vulnerabilities = append(bom.Vulnerabilities, v)
	}
}

func vulnerabilityKey(v Vulnerability) string {
	var affects []string
	for _, a := range v.Affects {
		affects = append(affects, a.Ref)
	}
	return v.ID + "::" + v.BOMRef + "::" + strings.Join(affects, ",")
}

func mergeDependencies(bom *BOM, incoming []CDXDependency) {
	byRef := map[string]int{}
	for i, dep := range bom.Dependencies {
		if dep.Ref != "" {
			byRef[dep.Ref] = i
		}
	}
	for _, dep := range incoming {
		if dep.Ref == "" {
			continue
		}
		if idx, ok := byRef[dep.Ref]; ok {
			bom.Dependencies[idx].DependsOn = mergeStringSlices(bom.Dependencies[idx].DependsOn, dep.DependsOn)
			continue
		}
		byRef[dep.Ref] = len(bom.Dependencies)
		bom.Dependencies = append(bom.Dependencies, dep)
	}
}

func mergeProperties(existing, incoming []Property) []Property {
	for _, prop := range incoming {
		existing = appendPropIfMissing(existing, prop.Name, prop.Value)
	}
	return existing
}

func mergeHashes(existing, incoming []Hash) []Hash {
	seen := map[string]bool{}
	for _, h := range existing {
		seen[h.Alg+"::"+h.Content] = true
	}
	for _, h := range incoming {
		key := h.Alg + "::" + h.Content
		if !seen[key] {
			seen[key] = true
			existing = append(existing, h)
		}
	}
	return existing
}

func mergeLicenses(existing, incoming []LicenseChoice) []LicenseChoice {
	seen := map[string]bool{}
	for _, l := range existing {
		seen[licenseKey(l)] = true
	}
	for _, l := range incoming {
		key := licenseKey(l)
		if !seen[key] {
			seen[key] = true
			existing = append(existing, l)
		}
	}
	return existing
}

func licenseKey(l LicenseChoice) string {
	if l.Expression != "" {
		return "expr:" + l.Expression
	}
	if l.License != nil {
		return "license:" + l.License.ID + ":" + l.License.Name + ":" + l.License.URL
	}
	return ""
}

func mergeContacts(existing, incoming []OrganizationalContact) []OrganizationalContact {
	seen := map[string]bool{}
	for _, c := range existing {
		seen[c.Name+"::"+c.Email] = true
	}
	for _, c := range incoming {
		key := c.Name + "::" + c.Email
		if !seen[key] {
			seen[key] = true
			existing = append(existing, c)
		}
	}
	return existing
}

func mergeExternalRefs(existing, incoming []ExternalReference) []ExternalReference {
	seen := map[string]bool{}
	for _, r := range existing {
		seen[r.Type+"::"+r.URL] = true
	}
	for _, r := range incoming {
		key := r.Type + "::" + r.URL
		if !seen[key] {
			seen[key] = true
			existing = append(existing, r)
		}
	}
	return existing
}

func mergeStringSlices(existing, incoming []string) []string {
	seen := map[string]bool{}
	for _, s := range existing {
		seen[s] = true
	}
	for _, s := range incoming {
		if !seen[s] {
			seen[s] = true
			existing = append(existing, s)
		}
	}
	return existing
}

// MergeUpstream returns local mutated with upstream's vulns and component
// gap-fills applied. It is safe to pass nil for either side — a nil local is
// initialised as an empty BOM; a nil upstream is a no-op.
//
// upstream is accepted as map[string]any because the API delivers an
// unmarshalled JSON object (not our local typed BOM struct) — see
// CliSCAResponse.CycloneDX in pkg/vdb/api_cli.go.
func MergeUpstream(local *BOM, upstream map[string]any) (*BOM, error) {
	if local == nil {
		local = &BOM{BOMFormat: "CycloneDX", SpecVersion: "1.6", Version: 1}
	}
	if len(upstream) == 0 {
		return local, nil
	}

	// Build a fast index over local components by all the keys we might match.
	type compRef struct {
		Index int
		Ref   string
	}
	byPurl := map[string]compRef{}
	byRef := map[string]compRef{}
	byNameVer := map[string]compRef{}
	for i, c := range local.Components {
		ref := c.BOMRef
		if ref == "" {
			ref = fmt.Sprintf("local-%d", i)
		}
		if c.Purl != "" {
			byPurl[c.Purl] = compRef{Index: i, Ref: ref}
		}
		if c.BOMRef != "" {
			byRef[c.BOMRef] = compRef{Index: i, Ref: ref}
		}
		if c.Name != "" {
			byNameVer[c.Name+"@"+c.Version] = compRef{Index: i, Ref: ref}
		}
	}

	// Walk upstream.components: fill local gaps and remember the upstream→local
	// ref mapping so we can rewrite vulnerability affects[].ref below.
	upstreamRefMap := map[string]string{} // upstream bom-ref → local bom-ref

	if ups, ok := upstream["components"].([]any); ok {
		for _, raw := range ups {
			obj, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			upPurl, _ := obj["purl"].(string)
			upRef, _ := obj["bom-ref"].(string)
			upName, _ := obj["name"].(string)
			upVer, _ := obj["version"].(string)

			var match *compRef
			if upPurl != "" {
				if v, hit := byPurl[upPurl]; hit {
					match = &v
				}
			}
			if match == nil && upRef != "" {
				if v, hit := byRef[upRef]; hit {
					match = &v
				}
			}
			if match == nil && upName != "" {
				if v, hit := byNameVer[upName+"@"+upVer]; hit {
					match = &v
				}
			}

			if match != nil {
				// Fill gaps on the matched local component.
				comp := &local.Components[match.Index]
				if comp.Purl == "" && upPurl != "" {
					comp.Purl = upPurl
				}
				if grp, ok := obj["group"].(string); ok && grp != "" {
					comp.Properties = appendPropIfMissing(comp.Properties, "cyclonedx:group", grp)
				}
				upstreamRefMap[upRef] = match.Ref
				continue
			}

			// Upstream-only component — translate verbatim into a local one.
			newComp := Component{
				Type:    coalesce(obj["type"], "library"),
				BOMRef:  upRef,
				Name:    upName,
				Version: upVer,
				Purl:    upPurl,
			}
			if newComp.BOMRef == "" {
				newComp.BOMRef = upPurl
				if newComp.BOMRef == "" {
					newComp.BOMRef = fmt.Sprintf("upstream-%d", len(local.Components))
				}
			}
			local.Components = append(local.Components, newComp)
			upstreamRefMap[upRef] = newComp.BOMRef
		}
	}

	// Append upstream vulnerabilities, rewriting affects.ref through the map.
	if uvs, ok := upstream["vulnerabilities"].([]any); ok {
		for _, raw := range uvs {
			obj, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			v := translateUpstreamVuln(obj, upstreamRefMap)
			if v != nil {
				local.Vulnerabilities = append(local.Vulnerabilities, *v)
			}
		}
	}

	return local, nil
}

func translateUpstreamVuln(obj map[string]any, refMap map[string]string) *Vulnerability {
	id, _ := obj["id"].(string)
	if id == "" {
		return nil
	}
	v := &Vulnerability{ID: id}
	if ref, ok := obj["bom-ref"].(string); ok {
		v.BOMRef = ref
	}
	if desc, ok := obj["description"].(string); ok {
		v.Description = desc
	}
	if src, ok := obj["source"].(map[string]any); ok {
		v.Source = &Source{
			Name: stringField(src, "name"),
			URL:  stringField(src, "url"),
		}
	}
	if ratings, ok := obj["ratings"].([]any); ok {
		for _, r := range ratings {
			rObj, ok := r.(map[string]any)
			if !ok {
				continue
			}
			rating := Rating{
				Method:   stringField(rObj, "method"),
				Severity: stringField(rObj, "severity"),
			}
			if s, ok := rObj["score"].(float64); ok {
				rating.Score = s
			}
			if s, ok := rObj["source"].(map[string]any); ok {
				rating.Source = &Source{Name: stringField(s, "name")}
			}
			v.Ratings = append(v.Ratings, rating)
		}
	}
	if affects, ok := obj["affects"].([]any); ok {
		for _, a := range affects {
			aObj, ok := a.(map[string]any)
			if !ok {
				continue
			}
			ref := stringField(aObj, "ref")
			if mapped, hit := refMap[ref]; hit {
				ref = mapped
			}
			if ref != "" {
				v.Affects = append(v.Affects, Affect{Ref: ref})
			}
		}
	}
	if refs, ok := obj["references"].([]any); ok {
		for _, ref := range refs {
			rObj, ok := ref.(map[string]any)
			if !ok {
				continue
			}
			if id := stringField(rObj, "id"); id != "" {
				srcName := ""
				if src, ok := rObj["source"].(map[string]any); ok {
					srcName = stringField(src, "name")
				}
				v.Properties = append(v.Properties, Property{
					Name:  "cyclonedx:reference:" + strings.ToLower(srcName),
					Value: id,
				})
			}
		}
	}
	return v
}

// appendPropIfMissing adds a property only if the same name+value pair is not
// already present — used for upstream gap-fills.
func appendPropIfMissing(props []Property, name, value string) []Property {
	for _, p := range props {
		if p.Name == name && p.Value == value {
			return props
		}
	}
	return append(props, Property{Name: name, Value: value})
}

func coalesce(v any, fallback string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return fallback
}

func stringField(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// ParseUpstreamFromJSON decodes a JSON CycloneDX document into the
// untyped map shape that MergeUpstream consumes. Useful when the upstream
// data arrived as raw bytes (e.g. read from disk) rather than via the
// CLI client.
func ParseUpstreamFromJSON(raw []byte) (map[string]any, error) {
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("parse upstream cdx: %w", err)
	}
	return out, nil
}
