package cdx

// Healing for CycloneDX documents that someone else's scanner produced.
//
// NormalizeForSchema (normalize.go) repairs a *BOM we are about to write. This
// file is the counterpart for a document we did not write and never decode into
// our own struct: `vulnetix gha upload` validates a third-party SBOM as raw bytes
// and then reads its inventory, so anything the schema rejects has to be repaired
// on the JSON before that validation runs.
//
// The pattern is the same either way: normalise, then validate, so the guard
// still catches bug classes we have not seen.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// NormalizeThirdPartyCDX heals a third-party CycloneDX document so that one
// malformed field does not cost the whole SBOM. An SBOM missing one bogus
// external reference is strictly better than no SBOM at all.
//
// Two classes are healed, both observed on real scanner output:
//
//   - externalReferences[].url that is not a valid iri-reference. ScanCode passes
//     an opam manifest's URL template through verbatim, producing entries like
//     "{https://opam.ocaml.org/packages}/{name}". There is no unambiguous
//     expansion of a template the scanner itself failed to expand, so the entry
//     is dropped. An external reference is metadata about a component, never the
//     component itself, so no inventory is lost.
//   - dependencies[].dependsOn listing the same ref twice. Trivy emits duplicate
//     refs and the schema types that array with uniqueItems, so the duplicates
//     are collapsed, keeping the first occurrence and the original order. The
//     edge is still there, so the graph is unchanged.
//
// Healing is keyed on the JSON key name at any depth, so nested components,
// services, metadata.component and the document root are all covered without
// hard-coding a path per spec version.
//
// It returns the healed bytes and one note per change, so a repair is reported
// rather than silent. When nothing needed healing the input bytes are returned
// unchanged, so a valid document is byte-for-byte untouched.
func NormalizeThirdPartyCDX(data []byte) ([]byte, []string) {
	var doc any
	dec := json.NewDecoder(bytes.NewReader(data))
	// Numbers stay json.Number so re-marshalling cannot rewrite an integer as a
	// float or push a large one into scientific notation.
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		// Not decodable JSON: leave it alone and let validation name it.
		return data, nil
	}

	var notes []string
	healCDXNode(doc, "", &notes)
	if len(notes) == 0 {
		return data, nil
	}

	out, err := json.Marshal(doc)
	if err != nil {
		return data, nil
	}
	return out, notes
}

// healCDXNode walks the decoded document, repairing the keys it recognises.
func healCDXNode(node any, path string, notes *[]string) {
	switch n := node.(type) {
	case map[string]any:
		for k, v := range n {
			child := path + "/" + k
			switch k {
			case "externalReferences":
				if arr, ok := v.([]any); ok {
					if kept, dropped := dropInvalidExternalRefs(arr, child, notes); dropped {
						// The key is optional everywhere it appears, so an array
						// emptied by the drop is removed rather than left bare.
						if len(kept) == 0 {
							delete(n, k)
							continue
						}
						n[k] = kept
					}
				}
			case "dependsOn":
				if arr, ok := v.([]any); ok {
					if deduped, removed := dedupeRefs(arr); removed > 0 {
						n[k] = deduped
						*notes = append(*notes, fmt.Sprintf(
							"%s: removed %d duplicate ref(s), the schema requires unique items", child, removed))
					}
				}
			}
			healCDXNode(n[k], child, notes)
		}
	case []any:
		for i, v := range n {
			healCDXNode(v, fmt.Sprintf("%s/%d", path, i), notes)
		}
	}
}

// dropInvalidExternalRefs removes every entry whose url the schema would reject,
// reporting each one. An entry with no url, or a non-string url, is left alone:
// that is a different bug class and validation should still name it.
func dropInvalidExternalRefs(arr []any, path string, notes *[]string) ([]any, bool) {
	kept := make([]any, 0, len(arr))
	dropped := false
	for i, item := range arr {
		if ref, ok := item.(map[string]any); ok {
			if u, ok := ref["url"].(string); ok && !validIRIReference(u) {
				*notes = append(*notes, fmt.Sprintf(
					"%s/%d: dropped externalReference, url %q is not a valid iri-reference", path, i, u))
				dropped = true
				continue
			}
		}
		kept = append(kept, item)
	}
	return kept, dropped
}

// dedupeRefs collapses repeated strings, keeping the first occurrence and the
// original order. A non-string entry is passed through untouched.
func dedupeRefs(arr []any) ([]any, int) {
	seen := make(map[string]bool, len(arr))
	out := make([]any, 0, len(arr))
	removed := 0
	for _, item := range arr {
		s, ok := item.(string)
		if !ok {
			out = append(out, item)
			continue
		}
		if seen[s] {
			removed++
			continue
		}
		seen[s] = true
		out = append(out, item)
	}
	return out, removed
}

// validIRIReference reports whether s passes the "iri-reference" format check the
// CycloneDX schemas apply to every externalReferences[].url.
//
// It mirrors santhosh-tekuri/jsonschema v6's validateURIReference, which is the
// implementation vdb-cyclonedx validates through: a backslash is rejected
// outright, the value must parse as a URL, and an IPv6 host must be bracketed.
// The library's deeper IPv6 address check is deliberately not reproduced, so a
// malformed bracketed address is left in place for validation to report rather
// than being healed on a guess.
func validIRIReference(s string) bool {
	if strings.Contains(s, `\`) {
		return false
	}
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	if host := u.Hostname(); strings.Contains(host, ":") {
		if !strings.Contains(u.Host, "[") || !strings.Contains(u.Host, "]") {
			return false
		}
	}
	return true
}
