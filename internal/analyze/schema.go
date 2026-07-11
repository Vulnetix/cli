// Package analyze produces the `vulnetix analyze` report: a repository's
// tech-stack graph, the cross-repo join keys other repositories match against,
// and the metrics for that repository — each metric carrying the evidence that
// produced it.
package analyze

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// schemaFS holds the report schema and the open schemas it extends. Authored in
// the repo's top-level schemas/ directory; `just sync-schemas` copies them here
// so they can be embedded. Never edit the copies.
//
//go:embed schemas/vulnetix-analyze-report.schema.json
//go:embed schemas/third_party/*.json
var schemaFS embed.FS

// ReportSchemaID is the $id of the report schema, and the URL it is published at.
const ReportSchemaID = "https://vulnetix.com/schemas/vulnetix-analyze-report.schema.json"

// schemaResources maps each embedded file to the URL it must be registered
// under. The URLs are not ours to choose: they are the $id each schema declares,
// and — for the three CycloneDX companions — the URLs that bom-1.7's relative
// $refs resolve to. Registering them under any other URL leaves those $refs
// dangling and the compile fails.
var schemaResources = map[string]string{
	"schemas/vulnetix-analyze-report.schema.json":                 ReportSchemaID,
	"schemas/third_party/sarif-2.1.0.schema.json":                 "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
	"schemas/third_party/openvex-0.2.0.schema.json":               "https://github.com/openvex/spec/openvex_json_schema_0.2.0.json",
	"schemas/third_party/cyclonedx-1.7.schema.json":               "http://cyclonedx.org/schema/bom-1.7.schema.json",
	"schemas/third_party/cyclonedx-spdx.schema.json":              "http://cyclonedx.org/schema/spdx.schema.json",
	"schemas/third_party/cyclonedx-jsf-0.82.schema.json":          "http://cyclonedx.org/schema/jsf-0.82.schema.json",
	"schemas/third_party/cyclonedx-cryptography-defs.schema.json": "http://cyclonedx.org/schema/cryptography-defs.schema.json",
	"schemas/third_party/spdx-2.3.schema.json":                    "http://spdx.org/rdf/terms/2.3",
	"schemas/third_party/ossf-scorecard-result.schema.json":       "https://vulnetix.com/schemas/third_party/ossf-scorecard-result.schema.json",
}

var (
	reportSchema    *jsonschema.Schema
	reportSchemaErr error
	reportSchemaMu  sync.Once
)

// CompiledReportSchema compiles the report schema together with every open
// schema it extends. The vendored schemas span three JSON Schema drafts (SARIF
// is draft-04, CycloneDX and SPDX draft-07, OpenVEX and ours 2020-12); each
// declares its own $schema and is resolved under its own dialect, so the mix is
// deliberate and must not be flattened.
func CompiledReportSchema() (*jsonschema.Schema, error) {
	reportSchemaMu.Do(func() {
		c := jsonschema.NewCompiler()
		for file, url := range schemaResources {
			raw, err := schemaFS.ReadFile(file)
			if err != nil {
				reportSchemaErr = fmt.Errorf("read embedded schema %s: %w", file, err)
				return
			}
			doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
			if err != nil {
				reportSchemaErr = fmt.Errorf("parse schema %s: %w", file, err)
				return
			}
			if err := c.AddResource(url, doc); err != nil {
				reportSchemaErr = fmt.Errorf("add schema resource %s (%s): %w", file, url, err)
				return
			}
		}
		s, err := c.Compile(ReportSchemaID)
		if err != nil {
			reportSchemaErr = fmt.Errorf("compile report schema: %w", err)
			return
		}
		reportSchema = s
	})
	return reportSchema, reportSchemaErr
}

// ValidateReport checks a marshalled report against the schema, and then against
// the one rule the schema cannot express.
//
// JSON Schema can require that a metric declares how its evidence relates to its
// value; it cannot check that the declaration is true, because that means
// comparing the length of one field against the value of a sibling. That check —
// a metric of 23 references 23 evidence items — is the whole point of the format,
// so it is enforced here and every report passes through it.
func ValidateReport(body []byte) error {
	s, err := CompiledReportSchema()
	if err != nil {
		return err
	}
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	if verr := s.Validate(doc); verr != nil {
		return fmt.Errorf("schema validation failed: %s", summariseSchemaError(verr))
	}

	var r struct {
		Metrics []struct {
			ID                   string `json:"id"`
			Value                any    `json:"value"`
			EvidenceSemantics    string `json:"evidenceSemantics"`
			EvidenceCompleteness string `json:"evidenceCompleteness"`
			PopulationSize       *int   `json:"populationSize"`
			OmittedCount         int    `json:"omittedCount"`
			EvidenceRefs         []any  `json:"evidenceRefs"`
		} `json:"metrics"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	var problems []string
	for _, m := range r.Metrics {
		if err := checkEvidenceCount(m.ID, m.Value, m.EvidenceSemantics, m.EvidenceCompleteness, m.PopulationSize, m.OmittedCount, len(m.EvidenceRefs)); err != nil {
			problems = append(problems, err.Error())
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("evidence invariant violated: %s", strings.Join(problems, "; "))
	}
	return nil
}

// checkEvidenceCount enforces the evidence invariant for one metric.
//
//   - instances:  the value counts the evidence, so the evidence must account for the value.
//   - population: the value is a statistic, so the evidence must account for the population it was computed over.
//   - assertion:  the value is a judgement with no countable relationship to its evidence; only the truncation
//     bookkeeping is checked.
//
// "Account for" means present plus omitted: an exhaustive metric carries every
// item, a truncated one carries the rest and says how many it dropped. A metric
// that quietly carries fewer than it claims is the failure this function exists
// to make impossible.
func checkEvidenceCount(id string, value any, semantics, completeness string, populationSize *int, omitted, refs int) error {
	truncated := completeness == "truncated"
	if !truncated && omitted != 0 {
		return fmt.Errorf("%s: omittedCount is set but evidenceCompleteness is %q", id, completeness)
	}

	var expected int
	switch semantics {
	case "assertion":
		return nil
	case "population":
		if populationSize == nil {
			return fmt.Errorf("%s: evidenceSemantics is population but populationSize is absent", id)
		}
		expected = *populationSize
	case "instances":
		n, ok := countableValue(value)
		if !ok {
			// A null value means the metric could not be measured; a non-numeric one
			// is not a count at all. Neither can be reconciled against an evidence
			// count, and neither should have been declared `instances`.
			if value == nil {
				if refs != 0 {
					return fmt.Errorf("%s: value is null but %d evidence items are attached", id, refs)
				}
				return nil
			}
			return fmt.Errorf("%s: evidenceSemantics is instances but value %v is not a whole number", id, value)
		}
		expected = n
	default:
		return fmt.Errorf("%s: unknown evidenceSemantics %q", id, semantics)
	}

	if got := refs + omitted; got != expected {
		if truncated {
			return fmt.Errorf("%s: expected %d evidence items, got %d present + %d omitted", id, expected, refs, omitted)
		}
		return fmt.Errorf("%s: expected %d evidence items, got %d", id, expected, refs)
	}
	return nil
}

// countableValue reports whether value is a non-negative whole number, and what
// it is. JSON has no integers, so a count arrives as a float64 and 23.0 is a
// count while 23.5 is not.
func countableValue(value any) (int, bool) {
	f, ok := value.(float64)
	if !ok || f < 0 || f != float64(int(f)) {
		return 0, false
	}
	return int(f), true
}

// summariseSchemaError flattens a validation error tree into a short single-line
// summary of the leaf failures.
func summariseSchemaError(verr error) string {
	ve, ok := verr.(*jsonschema.ValidationError)
	if !ok {
		return verr.Error()
	}
	const limit = 8
	var msgs []string
	var walk func(*jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		if len(msgs) >= limit {
			return
		}
		if len(e.Causes) == 0 {
			loc := "/" + strings.Join(e.InstanceLocation, "/")
			msgs = append(msgs, loc+": "+e.Error())
			return
		}
		for _, c := range e.Causes {
			walk(c)
		}
	}
	walk(ve)
	return strings.Join(msgs, "; ")
}
