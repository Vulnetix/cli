package attest

import (
	"encoding/json"
	"strings"
)

// predicate.go reads what an in-toto statement claims.
//
// A signature says who made an artefact. A predicate says how — which builder,
// from which source at which revision, under what parameters. That is the part
// a consumer actually reasons about, and it is worth reading even when the
// signature cannot be fully verified: knowing a document claims to come from a
// GitHub Actions workflow in a named repository is useful context, provided the
// distinction between "claims" and "proven" stays visible.
//
// Nothing here verifies anything. Everything it reports is a claim the payload
// makes, and the Result it attaches to carries the verification checks
// separately for exactly that reason.

// PredicateKind classifies a predicate by what it asserts.
type PredicateKind string

const (
	// KindProvenance — how an artefact was built (SLSA provenance).
	KindProvenance PredicateKind = "provenance"
	// KindSBOM — what an artefact contains.
	KindSBOM PredicateKind = "sbom"
	// KindOther — a predicate this CLI does not interpret.
	KindOther PredicateKind = "other"
)

// Subject is an artefact a statement is about.
type Subject struct {
	Name   string            `json:"name,omitempty"`
	Digest map[string]string `json:"digest,omitempty"`
}

// Predicate is the interpreted content of an in-toto statement.
type Predicate struct {
	// Type is the predicateType URI, verbatim.
	Type string `json:"type"`
	// Kind is what this CLI made of it.
	Kind PredicateKind `json:"kind"`
	// Subjects are the artefacts the statement is about.
	Subjects []Subject `json:"subjects,omitempty"`

	// Builder is who claims to have built the artefact, e.g. a GitHub Actions
	// workflow reference. Provenance only.
	Builder string `json:"builder,omitempty"`
	// BuildType is the build definition the builder followed.
	BuildType string `json:"buildType,omitempty"`
	// SourceURI and SourceRevision are where the inputs came from.
	SourceURI      string `json:"sourceUri,omitempty"`
	SourceRevision string `json:"sourceRevision,omitempty"`
	// Invocation is the entry point the build was started at.
	Invocation string `json:"invocation,omitempty"`

	// SLSAVersion is the provenance schema version: "v0.2" or "v1".
	SLSAVersion string `json:"slsaVersion,omitempty"`
}

// slsaPredicateTypes are the provenance predicate URIs this CLI reads.
var slsaPredicateTypes = map[string]string{
	"https://slsa.dev/provenance/v0.2": "v0.2",
	"https://slsa.dev/provenance/v1":   "v1",
}

// parsePredicate reads an in-toto statement, returning nil when the payload is
// not one.
func parsePredicate(payload []byte) *Predicate {
	if len(payload) == 0 {
		return nil
	}
	var stmt struct {
		Type          string          `json:"_type"`
		PredicateType string          `json:"predicateType"`
		Subject       []Subject       `json:"subject"`
		Predicate     json.RawMessage `json:"predicate"`
	}
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return nil
	}
	if stmt.PredicateType == "" && stmt.Type == "" {
		return nil
	}

	p := &Predicate{Type: stmt.PredicateType, Subjects: stmt.Subject, Kind: KindOther}

	if version, ok := slsaPredicateTypes[stmt.PredicateType]; ok {
		p.Kind = KindProvenance
		p.SLSAVersion = version
		if version == "v1" {
			parseSLSAv1(stmt.Predicate, p)
		} else {
			parseSLSAv02(stmt.Predicate, p)
		}
		return p
	}

	lower := strings.ToLower(stmt.PredicateType)
	for _, marker := range []string{"spdx", "cyclonedx", "/sbom"} {
		if strings.Contains(lower, marker) {
			p.Kind = KindSBOM
			return p
		}
	}
	return p
}

// parseSLSAv02 reads the v0.2 provenance shape.
func parseSLSAv02(raw json.RawMessage, p *Predicate) {
	var pred struct {
		Builder struct {
			ID string `json:"id"`
		} `json:"builder"`
		BuildType  string `json:"buildType"`
		Invocation struct {
			ConfigSource struct {
				URI        string            `json:"uri"`
				Digest     map[string]string `json:"digest"`
				EntryPoint string            `json:"entryPoint"`
			} `json:"configSource"`
		} `json:"invocation"`
	}
	if err := json.Unmarshal(raw, &pred); err != nil {
		return
	}
	p.Builder = pred.Builder.ID
	p.BuildType = pred.BuildType
	p.SourceURI = pred.Invocation.ConfigSource.URI
	p.SourceRevision = firstDigest(pred.Invocation.ConfigSource.Digest)
	p.Invocation = pred.Invocation.ConfigSource.EntryPoint
}

// parseSLSAv1 reads the v1 provenance shape.
//
// v1 moved the builder under runDetails and the source under
// buildDefinition.externalParameters, so the same facts live at different paths
// and one parser cannot serve both.
func parseSLSAv1(raw json.RawMessage, p *Predicate) {
	var pred struct {
		BuildDefinition struct {
			BuildType            string          `json:"buildType"`
			ExternalParameters   json.RawMessage `json:"externalParameters"`
			ResolvedDependencies []struct {
				URI    string            `json:"uri"`
				Digest map[string]string `json:"digest"`
			} `json:"resolvedDependencies"`
		} `json:"buildDefinition"`
		RunDetails struct {
			Builder struct {
				ID string `json:"id"`
			} `json:"builder"`
		} `json:"runDetails"`
	}
	if err := json.Unmarshal(raw, &pred); err != nil {
		return
	}
	p.Builder = pred.RunDetails.Builder.ID
	p.BuildType = pred.BuildDefinition.BuildType

	// The first resolved dependency is conventionally the source repository.
	if len(pred.BuildDefinition.ResolvedDependencies) > 0 {
		dep := pred.BuildDefinition.ResolvedDependencies[0]
		p.SourceURI = dep.URI
		p.SourceRevision = firstDigest(dep.Digest)
	}

	// externalParameters is deliberately schema-free in SLSA v1, so the fields
	// are read opportunistically rather than modelled.
	var params struct {
		Workflow struct {
			Ref        string `json:"ref"`
			Repository string `json:"repository"`
			Path       string `json:"path"`
		} `json:"workflow"`
	}
	if err := json.Unmarshal(pred.BuildDefinition.ExternalParameters, &params); err == nil {
		if p.SourceURI == "" {
			p.SourceURI = params.Workflow.Repository
		}
		p.Invocation = params.Workflow.Path
	}
}

// firstDigest returns a digest in "alg:value" form, preferring sha256.
func firstDigest(digests map[string]string) string {
	if v, ok := digests["sha256"]; ok {
		return "sha256:" + v
	}
	for alg, v := range digests {
		return alg + ":" + v
	}
	return ""
}

// SLSALevelClaim describes what a predicate's own content supports.
//
// This is deliberately not "the SLSA level of this artefact". A level is a
// property of the build platform and its controls, which no consumer can
// determine by reading a document the build produced. What can be said is which
// fields are present, and that is what this reports — so a caller gating on
// provenance gates on facts rather than on a number the artefact asserted about
// itself.
type SLSALevelClaim struct {
	// HasProvenance reports whether a provenance predicate was found at all.
	HasProvenance bool `json:"hasProvenance"`
	// HasBuilder, HasSource and HasSubjectDigest report the fields that make
	// provenance actionable.
	HasBuilder       bool `json:"hasBuilder"`
	HasSource        bool `json:"hasSource"`
	HasSubjectDigest bool `json:"hasSubjectDigest"`
	// Missing names the absent fields, so a shortfall is actionable.
	Missing []string `json:"missing,omitempty"`
}

// Complete reports whether every field is present.
func (c SLSALevelClaim) Complete() bool {
	return c.HasProvenance && c.HasBuilder && c.HasSource && c.HasSubjectDigest
}

// Claim summarises what a predicate's fields support.
func (p *Predicate) Claim() SLSALevelClaim {
	c := SLSALevelClaim{}
	if p == nil || p.Kind != KindProvenance {
		c.Missing = append(c.Missing, "provenance predicate")
		return c
	}
	c.HasProvenance = true

	c.HasBuilder = p.Builder != ""
	if !c.HasBuilder {
		c.Missing = append(c.Missing, "builder identity")
	}
	c.HasSource = p.SourceURI != "" && p.SourceRevision != ""
	if !c.HasSource {
		c.Missing = append(c.Missing, "source repository and revision")
	}
	for _, s := range p.Subjects {
		if len(s.Digest) > 0 {
			c.HasSubjectDigest = true
			break
		}
	}
	if !c.HasSubjectDigest {
		c.Missing = append(c.Missing, "subject digest")
	}
	return c
}
