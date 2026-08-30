package bom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/vulnetix/cli/v3/internal/cdx"
)

// Property names stamped onto a parsed document's metadata.
//
// Normalising SPDX into the CycloneDX model is lossy by construction. These
// properties are what makes it honest: a document that has been through this
// reader always says what it originally was, at which spec version, inside
// which envelope, and — via the digest — exactly which bytes it came from.
// `bom enrich` depends on the digest to assert fidelity, and `bom diff` uses it
// to notice it is being handed the same document twice.
const (
	PropSourceFormat   = "vulnetix:bom/source-format"
	PropSourceSpec     = "vulnetix:bom/source-spec-version"
	PropSourceEnvelope = "vulnetix:bom/source-envelope"
	PropSourceDigest   = "vulnetix:bom/source-digest"
	PropSourcePath     = "vulnetix:bom/source-path"
	PropPredicateType  = "vulnetix:bom/predicate-type"
)

// SourceInfo records what a Document was before normalisation.
type SourceInfo struct {
	// Path is where the document was read from. Empty for stdin.
	Path string `json:"path,omitempty"`
	// Format and SpecVersion are the original serialisation.
	Format      Format `json:"format"`
	SpecVersion string `json:"specVersion,omitempty"`
	// Envelope and PredicateType are set when the SBOM arrived inside an
	// attestation wrapper.
	Envelope      Envelope `json:"envelope,omitempty"`
	PredicateType string   `json:"predicateType,omitempty"`
	// Digest is the SHA-256 of the bytes as supplied — the outer envelope
	// included, not the unwrapped payload, because that is the artefact a user
	// can point at on disk.
	Digest string `json:"digest"`
	// Size is the length in bytes of those same supplied bytes.
	Size int `json:"size"`
}

// Document is a parsed SBOM in the canonical CycloneDX model.
type Document struct {
	BOM    *cdx.BOM   `json:"bom"`
	Source SourceInfo `json:"source"`
}

// Name returns the best available human label for the document's subject.
func (d *Document) Name() string {
	if d == nil || d.BOM == nil {
		return ""
	}
	if d.BOM.Metadata != nil && d.BOM.Metadata.Component != nil {
		if n := d.BOM.Metadata.Component.Name; n != "" {
			return n
		}
	}
	return ""
}

// Load reads and parses an SBOM from a file path.
func Load(path string) (*Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	doc, err := LoadBytes(data, path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return doc, nil
}

// LoadReader reads and parses an SBOM from a stream. path is used only for
// labelling and may be empty.
func LoadReader(r io.Reader, path string) (*Document, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return LoadBytes(data, path)
}

// LoadBytes parses an SBOM from bytes, unwrapping any attestation envelope.
func LoadBytes(data []byte, path string) (*Document, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty document")
	}
	det := Detect(data)
	if !det.Supported {
		return nil, &UnsupportedError{Format: det.Format, SpecVersion: det.SpecVersion}
	}

	sum := sha256.Sum256(data)
	src := SourceInfo{
		Path:          path,
		Format:        det.Format,
		SpecVersion:   det.SpecVersion,
		Envelope:      det.Envelope,
		PredicateType: det.PredicateType,
		Digest:        hex.EncodeToString(sum[:]),
		Size:          len(data),
	}

	var (
		bom *cdx.BOM
		err error
	)
	switch det.Format {
	case FormatCycloneDX:
		bom, err = parseCycloneDX(det.Payload)
	case FormatSPDX:
		bom, err = parseSPDX(det.Payload)
	default:
		return nil, &UnsupportedError{Format: det.Format, SpecVersion: det.SpecVersion}
	}
	if err != nil {
		return nil, err
	}

	stampSource(bom, src)
	return &Document{BOM: bom, Source: src}, nil
}

// parseCycloneDX decodes a CycloneDX JSON document into the canonical model.
//
// The canonical model *is* CycloneDX, so this is a decode rather than a
// conversion. Fields the internal model does not declare are dropped; that is
// deliberate and bounded — the model covers components, licenses, hashes,
// external references, properties, the dependency graph and vulnerabilities,
// which is everything downstream consumes.
func parseCycloneDX(data []byte) (*cdx.BOM, error) {
	var bom cdx.BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, fmt.Errorf("parsing CycloneDX: %w", err)
	}
	if bom.BOMFormat == "" {
		bom.BOMFormat = "CycloneDX"
	}
	if bom.Version == 0 {
		bom.Version = 1
	}
	ensureBOMRefs(&bom)
	return &bom, nil
}

// ensureBOMRefs gives every component a bom-ref.
//
// The dependency graph addresses components by ref, so a document whose
// components carry purls but no bom-refs — legal CycloneDX, and common from
// hand-rolled generators — would otherwise produce a graph that resolves to
// nothing. Preferring the purl matches what dedupeCDXPackages does on the write
// side, so a document that round-trips through this CLI keeps stable refs.
func ensureBOMRefs(bom *cdx.BOM) {
	seen := make(map[string]bool, len(bom.Components))
	for i := range bom.Components {
		if ref := bom.Components[i].BOMRef; ref != "" {
			seen[ref] = true
		}
	}
	for i := range bom.Components {
		c := &bom.Components[i]
		if c.BOMRef != "" {
			continue
		}
		candidate := c.Purl
		if candidate == "" {
			candidate = c.Name
			if c.Version != "" {
				candidate += "@" + c.Version
			}
		}
		if candidate == "" || seen[candidate] {
			candidate = fmt.Sprintf("vulnetix-ref-%d", i)
		}
		c.BOMRef = candidate
		seen[candidate] = true
	}
}

// stampSource records the original serialisation in the BOM's metadata.
func stampSource(bom *cdx.BOM, src SourceInfo) {
	if bom == nil {
		return
	}
	if bom.Metadata == nil {
		bom.Metadata = &cdx.Metadata{}
	}
	set := func(name, value string) {
		if value == "" {
			return
		}
		bom.Metadata.SetProperty(name, value)
	}
	set(PropSourceFormat, string(src.Format))
	set(PropSourceSpec, src.SpecVersion)
	set(PropSourceEnvelope, string(src.Envelope))
	set(PropSourceDigest, src.Digest)
	set(PropSourcePath, src.Path)
	set(PropPredicateType, src.PredicateType)
}
