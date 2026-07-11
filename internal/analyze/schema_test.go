package analyze

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The report schema $refs five open schemas across three JSON Schema drafts, and
// CycloneDX in turn $refs three companions by relative path. A single missing or
// misregistered resource leaves a dangling $ref, which surfaces only at compile
// time — so compiling is the test.
func TestReportSchemaCompiles(t *testing.T) {
	s, err := CompiledReportSchema()
	require.NoError(t, err)
	require.NotNil(t, s)
}

// The embedded copies are generated from schemas/ by `just sync-schemas`. If they
// drift, the CLI validates against a schema nobody is reading, and the published
// URL lies about what we accept.
func TestEmbeddedSchemasMatchSource(t *testing.T) {
	for file := range schemaResources {
		embedded, err := schemaFS.ReadFile(file)
		require.NoError(t, err, file)

		// schemas/foo.json in the embed FS is ../../schemas/foo.json in the repo.
		source, err := os.ReadFile(filepath.Join("..", "..", file))
		require.NoError(t, err, "authored schema missing for embedded %s", file)

		require.Equal(t, string(source), string(embedded),
			"%s is out of step with the authored schema — run `just sync-schemas`", file)
	}
}

func TestValidateReport_MinimalReportIsValid(t *testing.T) {
	require.NoError(t, ValidateReport(goldenReport(t, nil)))
}

// The invariant the whole format exists to enforce: a metric whose value is 3
// carries 3 evidence items. Drop one and the report must be rejected — a report
// that quietly under-reports its evidence is the failure mode every tool we
// surveyed has, and the one thing this schema is for.
func TestValidateReport_RejectsMissingEvidence(t *testing.T) {
	body := goldenReport(t, func(r map[string]any) {
		m := metric(r, 0)
		refs := m["evidenceRefs"].([]any)
		m["evidenceRefs"] = refs[:len(refs)-1]
	})

	err := ValidateReport(body)
	require.Error(t, err)
	require.Contains(t, err.Error(), "expected 3 evidence items, got 2")
}

// Attaching more evidence than the value claims is just as wrong, and just as
// silent, as attaching less.
func TestValidateReport_RejectsSurplusEvidence(t *testing.T) {
	body := goldenReport(t, func(r map[string]any) {
		m := metric(r, 0)
		m["value"] = 2
	})

	err := ValidateReport(body)
	require.Error(t, err)
	require.Contains(t, err.Error(), "expected 2 evidence items, got 3")
}

// Hitting a cap is allowed. Hitting one silently is not: a truncated metric must
// account for what it dropped, so present + omitted still reconciles to the value.
func TestValidateReport_TruncatedMetricMustAccountForOmissions(t *testing.T) {
	t.Run("declared omissions reconcile", func(t *testing.T) {
		body := goldenReport(t, func(r map[string]any) {
			m := metric(r, 0)
			m["value"] = 100
			m["evidenceCompleteness"] = "truncated"
			m["omittedCount"] = 97
			m["truncationReason"] = "evidence budget of 3 items exhausted"
		})
		require.NoError(t, ValidateReport(body))
	})

	t.Run("omissions that do not reconcile are rejected", func(t *testing.T) {
		body := goldenReport(t, func(r map[string]any) {
			m := metric(r, 0)
			m["value"] = 100
			m["evidenceCompleteness"] = "truncated"
			m["omittedCount"] = 50 // 3 present + 50 omitted != 100
			m["truncationReason"] = "evidence budget exhausted"
		})
		err := ValidateReport(body)
		require.Error(t, err)
		require.Contains(t, err.Error(), "got 3 present + 50 omitted")
	})

	t.Run("truncation without a reason is rejected by the schema", func(t *testing.T) {
		body := goldenReport(t, func(r map[string]any) {
			m := metric(r, 0)
			m["evidenceCompleteness"] = "truncated"
		})
		err := ValidateReport(body)
		require.Error(t, err)
		require.Contains(t, err.Error(), "schema validation failed")
	})
}

// A statistic is not a count: the evidence behind a median is the population it
// was computed over, not the median itself.
func TestValidateReport_PopulationMetricCountsItsPopulation(t *testing.T) {
	t.Run("population size is what the evidence must account for", func(t *testing.T) {
		body := goldenReport(t, func(r map[string]any) {
			m := metric(r, 0)
			m["id"] = "activity.time_to_first_response.median"
			m["family"] = "activity"
			m["unit"] = "seconds"
			m["statistic"] = "median"
			m["value"] = 86400 // a median of a day, over a population of 3 pull requests
			m["evidenceSemantics"] = "population"
			m["populationSize"] = 3
		})
		require.NoError(t, ValidateReport(body))
	})

	t.Run("a population metric with no population size is rejected", func(t *testing.T) {
		body := goldenReport(t, func(r map[string]any) {
			m := metric(r, 0)
			m["value"] = 86400
			m["evidenceSemantics"] = "population"
		})
		err := ValidateReport(body)
		require.Error(t, err)
		require.Contains(t, err.Error(), "schema validation failed")
	})
}

// A metric that could not be measured is null, and carries no evidence. It must
// never be reported as zero — "we found no secrets" and "we could not look for
// secrets" are different claims.
func TestValidateReport_NullValueMeansUnmeasured(t *testing.T) {
	t.Run("null with no evidence is valid", func(t *testing.T) {
		body := goldenReport(t, func(r map[string]any) {
			m := metric(r, 0)
			m["value"] = nil
			m["evidenceRefs"] = []any{}
		})
		require.NoError(t, ValidateReport(body))
	})

	t.Run("null with evidence attached is a contradiction", func(t *testing.T) {
		body := goldenReport(t, func(r map[string]any) {
			m := metric(r, 0)
			m["value"] = nil
		})
		err := ValidateReport(body)
		require.Error(t, err)
		require.Contains(t, err.Error(), "value is null but 3 evidence items are attached")
	})
}

// Every evidence kind in the union must actually resolve against its attachment
// or the inline store. The golden report exercises one of each.
func TestValidateReport_EveryEvidenceKindValidates(t *testing.T) {
	var r map[string]any
	require.NoError(t, json.Unmarshal(goldenReport(t, nil), &r))

	kinds := map[string]bool{}
	for _, ref := range metric(r, 0)["evidenceRefs"].([]any) {
		kinds[ref.(map[string]any)["kind"].(string)] = true
	}
	require.Equal(t, map[string]bool{"sarif": true, "vex": true, "record": true}, kinds)
}

func TestValidateReport_RejectsUnknownField(t *testing.T) {
	body := goldenReport(t, func(r map[string]any) {
		r["totallyNewTopLevelField"] = "surprise"
	})
	err := ValidateReport(body)
	require.Error(t, err)
	require.Contains(t, err.Error(), "schema validation failed")
}

func TestValidateReport_RejectsMalformedJSON(t *testing.T) {
	require.ErrorContains(t, ValidateReport([]byte("{not json")), "invalid JSON")
}

func TestValidateReport_RejectsBadRepoId(t *testing.T) {
	body := goldenReport(t, func(r map[string]any) {
		r["target"].(map[string]any)["repoId"] = "just-a-name"
	})
	require.ErrorContains(t, ValidateReport(body), "schema validation failed")
}

// metric returns metric i of the report for mutation in place.
func metric(r map[string]any, i int) map[string]any {
	return r["metrics"].([]any)[i].(map[string]any)
}

// goldenReport builds a valid report — one metric with a value of 3 and three
// evidence items, one of each addressable kind — and applies an optional mutation
// before marshalling. Tests state their intent as a diff against a good report
// rather than by hand-rolling a fresh one each time.
func goldenReport(t *testing.T, mutate func(map[string]any)) []byte {
	t.Helper()

	const src = `{
  "schemaVersion": "1.0.0",
  "tool": { "name": "vulnetix-analyze", "version": "3.58.0", "catalogVersion": "1" },
  "target": {
    "repoId": "github.com~vulnetix~cli",
    "orgKey": "github.com~vulnetix",
    "defaultBranch": "main",
    "headCommit": "1cda9720000000000000000000000000000000aa"
  },
  "run": {
    "startedAt": "2026-07-11T00:00:00Z",
    "completedAt": "2026-07-11T00:00:12Z",
    "durationSeconds": 12,
    "historyWindow": { "since": "2026-04-12T00:00:00Z", "until": "2026-07-11T00:00:00Z", "commitsWalked": 412 },
    "collectors": [{ "name": "git-history", "status": "completed" }]
  },
  "graph": {
    "nodes": [
      { "id": "dependency:pkg:golang/github.com/spf13/cobra@1.10.2", "kind": "dependency", "name": "cobra",
        "purl": "pkg:golang/github.com/spf13/cobra@1.10.2" }
    ],
    "edges": [],
    "crossRepoEdges": [
      { "id": "xr:1", "localNodeId": "dependency:pkg:golang/github.com/spf13/cobra@1.10.2",
        "joinKind": "package", "joinKey": "pkg:golang/github.com/spf13/cobra@1.10.2",
        "role": "consumes", "confidence": 1 }
    ]
  },
  "metrics": [
    {
      "id": "security.secrets.committed",
      "family": "security",
      "name": "Secrets committed to history",
      "definition": "Count of distinct secret findings across every commit reachable from HEAD within the history window.",
      "unit": "count",
      "value": 3,
      "evidenceSemantics": "instances",
      "evidenceCompleteness": "exhaustive",
      "evidenceRefs": [
        { "kind": "sarif", "runIndex": 0, "resultIndex": 0 },
        { "kind": "vex", "statementIndex": 0 },
        { "kind": "record", "recordId": "commit-1" }
      ]
    }
  ],
  "evidence": {
    "records": [
      {
        "id": "commit-1",
        "type": "commit",
        "sha": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "committedAt": "2026-05-01T10:00:00Z",
        "author": { "name": "Ada", "email": "ada@example.com", "isBot": false },
        "parentCount": 1
      }
    ]
  },
  "attachments": {
    "sarif": {
      "version": "2.1.0",
      "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
      "runs": [
        {
          "tool": { "driver": { "name": "vulnetix-analyze", "rules": [{ "id": "SECRET-AWS-KEY" }] } },
          "results": [
            {
              "ruleId": "SECRET-AWS-KEY",
              "level": "error",
              "message": { "text": "AWS access key committed" },
              "locations": [
                {
                  "physicalLocation": {
                    "artifactLocation": { "uri": "config/settings.yaml" },
                    "region": { "startLine": 12 }
                  }
                }
              ]
            }
          ]
        }
      ]
    },
    "openvex": {
      "@context": "https://openvex.dev/ns/v0.2.0",
      "@id": "https://vulnetix.com/vex/analyze/1",
      "author": "Vulnetix",
      "timestamp": "2026-07-11T00:00:12Z",
      "version": 1,
      "statements": [
        {
          "vulnerability": { "name": "CVE-2026-0001" },
          "products": [{ "@id": "pkg:golang/github.com/spf13/cobra@1.10.2" }],
          "status": "not_affected",
          "justification": "vulnerable_code_not_in_execute_path"
        }
      ]
    }
  },
  "diagnostics": [
    {
      "level": "note",
      "caveat": true,
      "message": "Squash-merge workflows flatten authorship: contributor counts reflect the merger, not the author."
    }
  ]
}`

	var r map[string]any
	require.NoError(t, json.NewDecoder(strings.NewReader(src)).Decode(&r))
	if mutate != nil {
		mutate(r)
	}
	body, err := json.Marshal(r)
	require.NoError(t, err)
	return body
}
