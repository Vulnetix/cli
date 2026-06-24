package cdx

// CycloneDX modelCard structs (spec 1.5+). These mirror the bundled
// vdb-cyclonedx schema, where modelCard / modelParameters / approach all set
// `additionalProperties: false`. Every field here is therefore a recognised
// schema key — do not add custom fields. Per-detection evidence belongs in the
// owning Component's `properties` array, not inside the model card.
//
// A modelCard MUST only ever be attached to a component of type
// "machine-learning-model"; the schema forbids it on any other component type.

// ModelCard describes the intended use and parameters of a machine learning
// model. For an AIBOM that records *consumption* of a hosted model (rather than
// a locally trained one), only the lightweight identification fields are known,
// so most of the card is intentionally left empty.
type ModelCard struct {
	BOMRef          string           `json:"bom-ref,omitempty"`
	ModelParameters *ModelParameters `json:"modelParameters,omitempty"`
}

// ModelParameters captures the architecture / task of the model. modelParameters
// is closed (additionalProperties:false) so only these keys are valid.
type ModelParameters struct {
	Approach           *Approach `json:"approach,omitempty"`
	Task               string    `json:"task,omitempty"`
	ArchitectureFamily string    `json:"architectureFamily,omitempty"`
	ModelArchitecture  string    `json:"modelArchitecture,omitempty"`
}

// Approach is the learning approach. Type must be one of the schema enum:
// supervised, unsupervised, reinforcement-learning, semi-supervised,
// self-supervised. Omitted for hosted models whose training regime is unknown.
type Approach struct {
	Type string `json:"type,omitempty"`
}
