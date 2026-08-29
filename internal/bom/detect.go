// Package bom is the read side of the SBOM story: it parses SBOM documents the
// CLI did not write.
//
// internal/cdx builds CycloneDX documents from a scanned working tree, and
// internal/license writes SPDX. Neither can consume one. Everything that
// follows from treating an SBOM as an *input* — diffing two releases, applying
// a third-party VEX to a supplied BOM, querying a directory of documents for
// version skew — needs a parser first, and this is it.
//
// One canonical model: everything parsed becomes a *cdx.BOM. SPDX in,
// CycloneDX model out. That keeps a single type flowing into license
// evaluation, VDB lookup, VEX application and diff, rather than each of them
// growing a second code path for the other serialisation. What the original
// document was is not lost — it is recorded on Document.Source and stamped into
// the BOM's metadata properties, so a normalised document still says where it
// came from.
package bom

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// Format identifies an SBOM serialisation.
type Format string

const (
	FormatCycloneDX Format = "cyclonedx"
	FormatSPDX      Format = "spdx"
	FormatUnknown   Format = "unknown"
)

// Envelope identifies an outer wrapper the SBOM arrived inside.
type Envelope string

const (
	// EnvelopeNone — the document is a bare SBOM.
	EnvelopeNone Envelope = ""
	// EnvelopeDSSE — a DSSE envelope: the in-toto Statement is base64 in
	// `payload`, alongside `signatures`. This is what `cosign attest` and
	// `syft attest` produce.
	EnvelopeDSSE Envelope = "dsse"
	// EnvelopeInToto — a bare in-toto Statement, predicate inline. This is what
	// BuildKit writes into an image's SBOM attestation layer, and what falls out
	// of a DSSE envelope once decoded.
	EnvelopeInToto Envelope = "in-toto"
)

// Detection is the result of sniffing a document.
type Detection struct {
	Format        Format
	SpecVersion   string
	Envelope      Envelope
	PredicateType string
	// Supported reports whether this CLI can parse the document. An
	// unsupported document still reports its Format and SpecVersion, so the
	// caller can say *which* version it could not read.
	Supported bool
	// Payload is the inner SBOM bytes. It equals the input when no envelope
	// was unwrapped, so callers can parse Payload unconditionally.
	Payload []byte
}

// supportedSPDXVersions are the SPDX spec versions the reader understands.
//
// 2.2 and 2.3 differ, for the fields this reader consumes, only in additions —
// package purls, relationships and license expressions are identical — so one
// parser serves both. SPDX 3.0 is a different document shape entirely and is
// deliberately absent rather than silently mis-parsed.
var supportedSPDXVersions = map[string]bool{
	"SPDX-2.2": true,
	"SPDX-2.3": true,
}

// supportedCDXVersions are the CycloneDX spec versions the reader understands.
//
// The reader is tolerant across the whole 1.x line because the fields it
// consumes — components, licenses, purls, the dependency graph — are stable
// from 1.0 onward. Documents are *written* at 1.6/1.7 (see cdx.ValidSpecVersions);
// refusing to read an older one would mean refusing most SBOMs in the wild.
var supportedCDXVersions = map[string]bool{
	"1.0": true, "1.1": true, "1.2": true, "1.3": true,
	"1.4": true, "1.5": true, "1.6": true, "1.7": true,
}

// maxEnvelopeDepth caps how many wrappers Detect will peel.
//
// A DSSE envelope containing an in-toto Statement is two, which is the deepest
// shape that occurs in practice. The cap exists so a hand-crafted document
// whose predicate is another envelope cannot spin the loop.
const maxEnvelopeDepth = 4

// Detect identifies an SBOM document, unwrapping any attestation envelope.
//
// Envelope unwrapping is the point of this function. A container SBOM produced
// by Syft or BuildKit is almost never a bare document — it arrives as an
// in-toto Statement whose `predicate` is the SBOM, often base64'd inside a DSSE
// envelope first. Sniffing for `bomFormat` at the top level misses all of them.
//
// Detect does not verify signatures. Unwrapping is parsing, not trust; a
// caller that needs the attestation checked calls internal/attest explicitly
// (`bom import --verify-attestation`), so that reading a document never
// implies believing it.
func Detect(data []byte) Detection {
	payload := data
	env := EnvelopeNone
	predicateType := ""

	for depth := 0; depth < maxEnvelopeDepth; depth++ {
		inner, kind, ptype, ok := unwrapEnvelope(payload)
		if !ok {
			break
		}
		payload = inner
		predicateType = ptype
		// The outermost wrapper is the one worth reporting: a document that
		// arrived DSSE-signed is DSSE-enveloped even though a bare in-toto
		// Statement fell out of it.
		if env == EnvelopeNone {
			env = kind
		}
	}

	det := sniff(payload)
	det.Envelope = env
	det.PredicateType = predicateType
	det.Payload = payload
	return det
}

// sniff classifies a bare (unwrapped) document.
func sniff(data []byte) Detection {
	var probe struct {
		SPDXVersion string          `json:"spdxVersion"`
		SPDXID      json.RawMessage `json:"SPDXID"`
		BOMFormat   string          `json:"bomFormat"`
		SpecVersion string          `json:"specVersion"`
		Components  json.RawMessage `json:"components"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return Detection{Format: FormatUnknown}
	}

	if probe.SPDXVersion != "" && len(probe.SPDXID) > 0 {
		return Detection{
			Format:      FormatSPDX,
			SpecVersion: probe.SPDXVersion,
			Supported:   supportedSPDXVersions[probe.SPDXVersion],
		}
	}

	// A CycloneDX document is identified by bomFormat, but 1.0 and 1.1 JSON
	// predate that field; specVersion plus a components array is the fallback
	// those two answer to.
	if probe.BOMFormat == "CycloneDX" || (probe.SpecVersion != "" && len(probe.Components) > 0) {
		return Detection{
			Format:      FormatCycloneDX,
			SpecVersion: probe.SpecVersion,
			Supported:   supportedCDXVersions[probe.SpecVersion],
		}
	}

	return Detection{Format: FormatUnknown}
}

// unwrapEnvelope peels one attestation wrapper, returning the inner document.
//
// The bool reports whether anything was unwrapped; when false the other returns
// are meaningless and the caller keeps the document it had.
func unwrapEnvelope(data []byte) (inner []byte, kind Envelope, predicateType string, ok bool) {
	var probe struct {
		PayloadType   string          `json:"payloadType"`
		Payload       string          `json:"payload"`
		Type          string          `json:"_type"`
		PredicateType string          `json:"predicateType"`
		Predicate     json.RawMessage `json:"predicate"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, EnvelopeNone, "", false
	}

	// DSSE: base64 payload plus a payloadType naming in-toto.
	if probe.Payload != "" && strings.Contains(probe.PayloadType, "in-toto") {
		decoded, err := base64.StdEncoding.DecodeString(probe.Payload)
		if err != nil {
			// Signed but undecodable is a corrupt envelope, not a bare SBOM.
			// Report no unwrap and let sniff fail on the original bytes.
			return nil, EnvelopeNone, "", false
		}
		return decoded, EnvelopeDSSE, probe.PredicateType, true
	}

	// Bare in-toto Statement: predicate carries the SBOM.
	if len(probe.Predicate) > 0 && (probe.Type != "" || probe.PredicateType != "") {
		if !predicateCarriesSBOM(probe.PredicateType) {
			return nil, EnvelopeNone, "", false
		}
		return probe.Predicate, EnvelopeInToto, probe.PredicateType, true
	}

	return nil, EnvelopeNone, "", false
}

// predicateCarriesSBOM reports whether a predicateType names an SBOM predicate.
//
// Matching on substrings rather than an exact set is deliberate: the predicate
// type is a versioned URI (https://spdx.dev/Document, .../cyclonedx,
// https://in-toto.io/attestation/sbom/v0.1 and several vendor spellings), and a
// closed list would reject next year's URI for a document this parser can read
// perfectly well. An empty predicateType is accepted too — BuildKit omits it —
// because sniff still has the final say on whether the payload is an SBOM.
func predicateCarriesSBOM(predicateType string) bool {
	if predicateType == "" {
		return true
	}
	lower := strings.ToLower(predicateType)
	for _, marker := range []string{"spdx", "cyclonedx", "/sbom", "bom"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// UnsupportedError reports a document this CLI recognised but cannot parse.
type UnsupportedError struct {
	Format      Format
	SpecVersion string
}

func (e *UnsupportedError) Error() string {
	switch e.Format {
	case FormatUnknown:
		return "not a recognised SBOM: expected a CycloneDX or SPDX JSON document"
	case FormatSPDX:
		return fmt.Sprintf("unsupported SPDX version %q: this CLI reads SPDX-2.2 and SPDX-2.3", e.SpecVersion)
	default:
		return fmt.Sprintf("unsupported %s version %q", e.Format, e.SpecVersion)
	}
}
