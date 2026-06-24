package cdx

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// AIBOM (AI Bill of Materials) construction.
//
// The input types below are the contract between the detection layer
// (internal/aibom, which has no knowledge of CycloneDX) and this builder. The
// detector populates AIDetections; BuildAIBOM maps it to a CycloneDX BOM:
//
//	AI coding tool/agent  -> component type "application"
//	AI SDK / framework     -> component type "library"
//	model name (literal)   -> component type "machine-learning-model" + modelCard
//
// Custom evidence rides on each component's `properties` (namespace vulnetix:ai/*).

// AIEvidence is one observation supporting a detection. Method is one of
// env|file|source. For file evidence Category is the catalog path category
// (config, instructions, agents, ...). For source evidence Category is
// import|model. Locator is an env var name, a file path, or "file:line".
type AIEvidence struct {
	Method   string `json:"method"`
	Category string `json:"category,omitempty"`
	Locator  string `json:"locator,omitempty"`
	Snippet  string `json:"snippet,omitempty"`
}

// AITool is a detected AI coding agent / assistant.
type AITool struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Vendor   string `json:"vendor,omitempty"`
	Type     string `json:"type,omitempty"`
	Homepage string `json:"homepage,omitempty"`
	// ArtifactCounts records discovered sub-artifacts per category
	// (agents, skills, commands, hooks, ...).
	ArtifactCounts map[string]int `json:"artifactCounts,omitempty"`
	Confidence     string         `json:"confidence,omitempty"`
	Evidence       []AIEvidence   `json:"evidence,omitempty"`
}

// AILibrary is a detected AI SDK / framework used by the source code.
type AILibrary struct {
	ID         string       `json:"id"`
	Name       string       `json:"name"`
	Provider   string       `json:"provider,omitempty"`
	Languages  []string     `json:"languages,omitempty"`
	Purl       string       `json:"purl,omitempty"`
	Confidence string       `json:"confidence,omitempty"`
	Evidence   []AIEvidence `json:"evidence,omitempty"`
}

// AIModel is a model name literal extracted from source or config.
type AIModel struct {
	Name        string       `json:"name"`
	Provider    string       `json:"provider,omitempty"`
	Family      string       `json:"family,omitempty"`
	ViaSDK      string       `json:"viaSdk,omitempty"`
	Task        string       `json:"task,omitempty"`
	Known       bool         `json:"known"`
	Occurrences int          `json:"occurrences,omitempty"`
	Confidence  string       `json:"confidence,omitempty"`
	Evidence    []AIEvidence `json:"evidence,omitempty"`
}

// AIDetections is the full result of an AIBOM scan.
type AIDetections struct {
	Tools          []AITool    `json:"tools,omitempty"`
	Libraries      []AILibrary `json:"libraries,omitempty"`
	Models         []AIModel   `json:"models,omitempty"`
	CatalogVersion string      `json:"catalogVersion,omitempty"`
}

// maxEvidencePerComponent caps how many evidence properties a single component
// carries, so a repo with thousands of call sites can't bloat the BOM.
const maxEvidencePerComponent = 50

// BuildAIBOM maps detection results to a CycloneDX BOM. The result is schema
// valid for the declared specVersion (default 1.7) — callers should serialise
// with MarshalValidatedJSON to enforce that at write time.
func BuildAIBOM(det AIDetections, specVersion string, ctx *ScanContext) (*BOM, error) {
	if specVersion == "" {
		specVersion = "1.7"
	}

	toolName := "vulnetix-aibom"
	toolVersion := "cli"
	if ctx != nil {
		if ctx.ToolName != "" {
			toolName = ctx.ToolName
		}
		if ctx.ToolVersion != "" {
			toolVersion = ctx.ToolVersion
		}
	}

	bom := &BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  specVersion,
		SerialNumber: "urn:uuid:" + uuid.New().String(),
		Version:      1,
		Metadata: &Metadata{
			Timestamp:  time.Now().UTC().Format(time.RFC3339),
			Lifecycles: []Lifecycle{{Phase: "build"}},
			Tools: &Tools{
				Components: []Component{
					{Type: "application", Name: toolName, Version: toolVersion},
				},
			},
		},
	}

	// Reuse the existing git/host enrichment for metadata.component.
	populateMetadataFromContext(bom.Metadata, ctx)
	if bom.Metadata.Component == nil {
		bom.Metadata.Component = &Component{Type: "application", BOMRef: "urn:project", Name: "project"}
	}
	if bom.Metadata.Component.BOMRef == "" {
		bom.Metadata.Component.BOMRef = "urn:project"
	}
	projRef := bom.Metadata.Component.BOMRef

	bom.Metadata.Properties = append(bom.Metadata.Properties,
		prop("vulnetix:aibom/profile", "ai-usage"),
		prop("vulnetix:aibom/generator", toolName),
	)
	if det.CatalogVersion != "" {
		bom.Metadata.Properties = append(bom.Metadata.Properties,
			prop("vulnetix:aibom/catalog-version", det.CatalogVersion))
	}
	bom.Metadata.Properties = append(bom.Metadata.Properties,
		prop("vulnetix:aibom/tools-detected", strconv.Itoa(len(det.Tools))),
		prop("vulnetix:aibom/libraries-detected", strconv.Itoa(len(det.Libraries))),
		prop("vulnetix:aibom/models-detected", strconv.Itoa(len(det.Models))),
	)

	validRefs := map[string]bool{projRef: true}
	deps := map[string][]string{}

	// ── AI coding tools / agents → application components ────────────────
	for _, t := range det.Tools {
		ref := "urn:ai-tool:" + t.ID
		comp := Component{
			Type:      "application",
			BOMRef:    ref,
			Name:      t.Name,
			Publisher: t.Vendor,
			Group:     t.Vendor,
		}
		if t.Homepage != "" {
			comp.ExternalReferences = append(comp.ExternalReferences,
				ExternalReference{Type: "website", URL: t.Homepage})
		}
		category := "coding-agent"
		switch t.Type {
		case "service":
			category = "ai-service"
		case "convention":
			category = "ai-convention"
		}
		comp.Properties = append(comp.Properties,
			prop("vulnetix:ai/category", category),
			prop("vulnetix:ai/tool-id", t.ID))
		if t.Type != "" {
			comp.Properties = append(comp.Properties, prop("vulnetix:ai/tool-type", t.Type))
		}
		if t.Confidence != "" {
			comp.Properties = append(comp.Properties, prop("vulnetix:ai/confidence", t.Confidence))
		}
		for _, k := range sortedKeys(t.ArtifactCounts) {
			comp.Properties = append(comp.Properties,
				prop("vulnetix:ai/discovered/"+k, strconv.Itoa(t.ArtifactCounts[k])))
		}
		appendEvidence(&comp, t.Evidence)
		bom.Components = append(bom.Components, comp)
		validRefs[ref] = true
		deps[projRef] = append(deps[projRef], ref)
	}

	// ── AI SDKs / frameworks → library components ────────────────────────
	libRefByID := map[string]string{}
	for _, l := range det.Libraries {
		ref := "urn:ai-lib:" + l.ID
		comp := Component{
			Type:      "library",
			BOMRef:    ref,
			Name:      l.Name,
			Publisher: l.Provider,
			Purl:      l.Purl,
		}
		comp.Properties = append(comp.Properties,
			prop("vulnetix:ai/category", "ai-sdk"),
			prop("vulnetix:ai/library-id", l.ID))
		if l.Provider != "" {
			comp.Properties = append(comp.Properties, prop("vulnetix:ai/provider", l.Provider))
		}
		if len(l.Languages) > 0 {
			comp.Properties = append(comp.Properties, prop("vulnetix:ai/languages", strings.Join(l.Languages, ",")))
		}
		if l.Confidence != "" {
			comp.Properties = append(comp.Properties, prop("vulnetix:ai/confidence", l.Confidence))
		}
		appendEvidence(&comp, l.Evidence)
		bom.Components = append(bom.Components, comp)
		validRefs[ref] = true
		libRefByID[l.ID] = ref
		deps[projRef] = append(deps[projRef], ref)
	}

	// ── model name literals → machine-learning-model components ──────────
	for i, m := range det.Models {
		ref := fmt.Sprintf("urn:ai-model:%d", i)
		comp := Component{
			Type:      "machine-learning-model",
			BOMRef:    ref,
			Name:      m.Name,
			Publisher: m.Provider,
			Group:     m.Provider,
			ModelCard: &ModelCard{
				ModelParameters: &ModelParameters{
					Task:              m.Task,
					ModelArchitecture: m.Name,
				},
			},
		}
		comp.Properties = append(comp.Properties,
			prop("vulnetix:ai/category", "model"),
			prop("vulnetix:ai/model/known", boolStr(m.Known)))
		if m.Provider != "" {
			comp.Properties = append(comp.Properties, prop("vulnetix:ai/provider", m.Provider))
		}
		if m.Family != "" {
			comp.Properties = append(comp.Properties, prop("vulnetix:ai/model/family", m.Family))
		}
		if m.ViaSDK != "" {
			comp.Properties = append(comp.Properties, prop("vulnetix:ai/model/via-sdk", m.ViaSDK))
		}
		if m.Occurrences > 0 {
			comp.Properties = append(comp.Properties, prop("vulnetix:ai/model/occurrences", strconv.Itoa(m.Occurrences)))
		}
		if m.Confidence != "" {
			comp.Properties = append(comp.Properties, prop("vulnetix:ai/confidence", m.Confidence))
		}
		appendEvidence(&comp, m.Evidence)
		bom.Components = append(bom.Components, comp)
		validRefs[ref] = true

		// Link the model under the SDK that invoked it when known, else the project.
		parent := projRef
		if r, ok := libRefByID[m.ViaSDK]; ok {
			parent = r
		}
		deps[parent] = append(deps[parent], ref)
	}

	bom.Dependencies = buildDependencies(deps, validRefs)
	return bom, nil
}

// appendEvidence records up to maxEvidencePerComponent evidence entries as
// component properties (properties allow duplicate names). A trailing count
// property records how many were observed in total.
func appendEvidence(comp *Component, ev []AIEvidence) {
	if len(ev) == 0 {
		return
	}
	comp.Properties = append(comp.Properties, prop("vulnetix:ai/evidence-count", strconv.Itoa(len(ev))))
	limit := min(len(ev), maxEvidencePerComponent)
	for _, e := range ev[:limit] {
		comp.Properties = append(comp.Properties, prop("vulnetix:ai/evidence", formatEvidence(e)))
	}
}

// formatEvidence renders one evidence record as a compact, single-line value:
//
//	"<method> <category> <locator> :: <snippet>"
func formatEvidence(e AIEvidence) string {
	var b strings.Builder
	b.WriteString(e.Method)
	if e.Category != "" {
		b.WriteString(" ")
		b.WriteString(e.Category)
	}
	if e.Locator != "" {
		b.WriteString(" ")
		b.WriteString(e.Locator)
	}
	if e.Snippet != "" {
		b.WriteString(" :: ")
		b.WriteString(e.Snippet)
	}
	return b.String()
}

// buildDependencies turns the adjacency map into a sorted, deduped CycloneDX
// dependency graph, dropping any edge whose target is not a real component.
func buildDependencies(deps map[string][]string, validRefs map[string]bool) []CDXDependency {
	out := make([]CDXDependency, 0, len(deps))
	for ref := range deps {
		if !validRefs[ref] {
			continue
		}
		seen := map[string]bool{}
		var on []string
		for _, t := range deps[ref] {
			if t == ref || seen[t] || !validRefs[t] {
				continue
			}
			seen[t] = true
			on = append(on, t)
		}
		sort.Strings(on)
		out = append(out, CDXDependency{Ref: ref, DependsOn: on})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out
}

func sortedKeys(m map[string]int) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
