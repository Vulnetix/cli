package cdx

import cyclonedx "github.com/Vulnetix/vdb-cyclonedx"

// The CycloneDX document model is owned by vdb-cyclonedx.
//
// These are aliases, not wrappers: cdx.BOM and cyclonedx.Document are the same
// type, so every composite literal in this repository compiles unchanged, and a
// document handed to the shared builders is not narrowed on the way through.
//
// This package used to declare the model itself. Two declarations of one shape
// is two sets of omissions, and they did not match: the local one had no
// metadata.manufacturer and no metadata.supplier, which is most of what
// CycloneDX uses to say who produced a document. Worse, it was lossy — decoding
// a third-party BOM into it dropped every member it did not declare — and that
// lossiness is why internal/scanopts carried a second, map-based implementation
// of deployment labelling rather than reuse ApplyDeploymentContext. The shared
// model round-trips unmodelled members, so one implementation suffices.
//
// What stays in this package is what is genuinely this CLI's: which lifecycle
// phase a scan captured, how git and host context become metadata, how two
// documents merge, and the vulnetix:* property vocabulary.
type (
	BOM                   = cyclonedx.Document
	Metadata              = cyclonedx.Metadata
	Component             = cyclonedx.Component
	Tools                 = cyclonedx.Tools
	Lifecycle             = cyclonedx.Lifecycle
	OrganizationalContact = cyclonedx.OrganizationalContact
	OrganizationalEntity  = cyclonedx.OrganizationalEntity
	Property              = cyclonedx.Property
	Hash                  = cyclonedx.Hash
	ExternalReference     = cyclonedx.ExternalReference
	LicenseChoice         = cyclonedx.LicenseChoice
	LicenseData           = cyclonedx.LicenseData
	CDXDependency         = cyclonedx.Dependency

	// Vulnerability and its parts. Rating.Score is a *float64 here where this
	// package used to declare a float64: an unscored rating is common, and a
	// value type emitted "score": 0 next to "severity": "high", which asserts a
	// score of zero rather than the absence of one.
	Vulnerability = cyclonedx.Vulnerability
	Source        = cyclonedx.VulnSource
	Rating        = cyclonedx.Rating
	Affect        = cyclonedx.Affect
	Analysis      = cyclonedx.Analysis
	Advisory      = cyclonedx.Advisory

	// CycloneDX modelCard (spec 1.5+). modelCard / modelParameters / approach all
	// set additionalProperties:false, so every field is a recognised schema key —
	// per-detection evidence belongs in the owning component's properties array,
	// never inside the model card. A modelCard may only be attached to a
	// component of type "machine-learning-model".
	ModelCard       = cyclonedx.ModelCard
	ModelParameters = cyclonedx.ModelParameters
	Approach        = cyclonedx.Approach
)

// Score wraps a rating score for the pointer field, so call sites that have a
// number stay one line. A rating with no score omits the member entirely rather
// than claiming zero.
func Score(v float64) *float64 { return &v }
