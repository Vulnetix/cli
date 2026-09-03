package cmd

import (
	"testing"
	"time"

	cyclonedx "github.com/Vulnetix/vdb-cyclonedx"
	"github.com/vulnetix/cli/v3/internal/suppress"
)

func inventorySet(rules ...suppress.Rule) *suppress.Set {
	for i := range rules {
		rules[i].IsActive = true
	}
	return suppress.NewSet(rules, time.Now().Unix())
}

func TestFilterSuppressedCryptoDetections(t *testing.T) {
	det := cyclonedx.CryptoDetections{
		Assets: []cyclonedx.CryptoAsset{
			{SPDXID: "SHA-1", Name: "SHA-1", PQCStatus: cyclonedx.PQCDeprecated,
				Evidence: []cyclonedx.CryptoEvidence{{Method: "source", Locator: "src/hash.go:12"}}},
			{SPDXID: "SHA-256", Name: "SHA-256", PQCStatus: cyclonedx.PQCQuantumSafe},
		},
		Certificates: []cyclonedx.CryptoCert{
			{Name: "legacy.pem", Subject: "CN=legacy", SignatureAlgorithm: "SHA-1"},
		},
		Libraries: []cyclonedx.CryptoLib{
			{ID: "openssl", Name: "OpenSSL", Purl: "pkg:generic/openssl"},
		},
	}

	// One rule, anchored by value, reaches the algorithm AND the certificate
	// whose signature algorithm carries the same name — both are genuinely that
	// algorithm, which is what the user asked to stop seeing.
	set := inventorySet(suppress.Rule{Category: "crypto", TargetValue: "SHA-1"})
	dropped := filterSuppressedCryptoDetections(&det, set)

	if dropped != 2 {
		t.Fatalf("expected 2 dropped, got %d", dropped)
	}
	if len(det.Assets) != 1 || det.Assets[0].SPDXID != "SHA-256" {
		t.Errorf("expected only SHA-256 to survive, got %+v", det.Assets)
	}
	if len(det.Certificates) != 0 {
		t.Errorf("expected the SHA-1-signed certificate to be dropped, got %+v", det.Certificates)
	}
	if len(det.Libraries) != 1 {
		t.Errorf("an unrelated library must survive, got %+v", det.Libraries)
	}

	// The posture rollup is the caller's job to recompute; verify it agrees with
	// what survived, since --fail-on gates on it.
	if s := cyclonedx.ComputeCryptoSummary(det); s.Deprecated != 0 || s.QuantumSafe != 1 {
		t.Errorf("recomputed summary should describe only what was kept, got %+v", s)
	}
}

func TestFilterSuppressedCryptoDetections_FileAnchor(t *testing.T) {
	det := cyclonedx.CryptoDetections{
		Assets: []cyclonedx.CryptoAsset{
			{SPDXID: "MD5", Name: "MD5", Evidence: []cyclonedx.CryptoEvidence{{Locator: "test/fixtures.go:4"}}},
			{SPDXID: "MD5", Name: "MD5", Evidence: []cyclonedx.CryptoEvidence{{Locator: "src/auth.go:99"}}},
		},
	}
	set := inventorySet(suppress.Rule{Category: "crypto", TargetValue: "MD5", FilePath: "test/fixtures.go"})

	if dropped := filterSuppressedCryptoDetections(&det, set); dropped != 1 {
		t.Fatalf("expected 1 dropped, got %d", dropped)
	}
	if len(det.Assets) != 1 || det.Assets[0].Evidence[0].Locator != "src/auth.go:99" {
		t.Errorf("the file-anchored rule should have spared src/auth.go, got %+v", det.Assets)
	}
}

func TestFilterSuppressedAIDetections(t *testing.T) {
	det := cyclonedx.AIDetections{
		Tools:          []cyclonedx.AITool{{ID: "cursor", Name: "Cursor"}, {ID: "claude-code", Name: "Claude Code"}},
		Libraries:      []cyclonedx.AILibrary{{ID: "openai-python", Name: "openai", Purl: "pkg:pypi/openai"}},
		Models:         []cyclonedx.AIModel{{Name: "gpt-4o"}, {Name: "claude-opus-4"}},
		Infrastructure: []cyclonedx.AIInfra{{ID: "vllm", Name: "vLLM", Image: "vllm/vllm-openai"}},
		Data:           []cyclonedx.AIData{{Name: "training-set", MountPath: "/data"}},
	}

	set := inventorySet(
		suppress.Rule{Category: "ai", TargetValue: "gpt-4o"},
		suppress.Rule{Category: "ai", TargetValue: "Cursor"},
		suppress.Rule{Category: "ai", TargetValue: "pkg:pypi/openai"},
	)
	dropped := filterSuppressedAIDetections(&det, set)

	if dropped != 3 {
		t.Fatalf("expected 3 dropped, got %d", dropped)
	}
	if len(det.Tools) != 1 || det.Tools[0].Name != "Claude Code" {
		t.Errorf("expected only Claude Code to survive, got %+v", det.Tools)
	}
	if len(det.Libraries) != 0 {
		t.Errorf("expected the purl-anchored SDK to be dropped, got %+v", det.Libraries)
	}
	if len(det.Models) != 1 || det.Models[0].Name != "claude-opus-4" {
		t.Errorf("expected only claude-opus-4 to survive, got %+v", det.Models)
	}
	if len(det.Infrastructure) != 1 || len(det.Data) != 1 {
		t.Error("unrelated infrastructure and data must survive")
	}
}

// A crypto rule must not reach AI components and vice versa: category is part
// of the anchor, not decoration.
func TestInventoryFilters_CategoryIsolation(t *testing.T) {
	ai := cyclonedx.AIDetections{Models: []cyclonedx.AIModel{{Name: "SHA-1"}}}
	if n := filterSuppressedAIDetections(&ai, inventorySet(
		suppress.Rule{Category: "crypto", TargetValue: "SHA-1"},
	)); n != 0 {
		t.Errorf("a crypto rule must not drop an AI component, dropped %d", n)
	}

	crypto := cyclonedx.CryptoDetections{Assets: []cyclonedx.CryptoAsset{{SPDXID: "SHA-1", Name: "SHA-1"}}}
	if n := filterSuppressedCryptoDetections(&crypto, inventorySet(
		suppress.Rule{Category: "ai", TargetValue: "SHA-1"},
	)); n != 0 {
		t.Errorf("an AI rule must not drop a crypto component, dropped %d", n)
	}
}

// An empty or nil set is the common case (most orgs have no inventory rules)
// and must be a no-op rather than a panic or a silent wipe.
func TestInventoryFilters_NoRulesIsNoOp(t *testing.T) {
	crypto := cyclonedx.CryptoDetections{Assets: []cyclonedx.CryptoAsset{{SPDXID: "SHA-1", Name: "SHA-1"}}}
	if n := filterSuppressedCryptoDetections(&crypto, inventorySet()); n != 0 || len(crypto.Assets) != 1 {
		t.Error("an empty set must drop nothing")
	}
	if n := filterSuppressedCryptoDetections(&crypto, nil); n != 0 || len(crypto.Assets) != 1 {
		t.Error("a nil set must drop nothing")
	}
	if n := filterSuppressedCryptoDetections(nil, inventorySet()); n != 0 {
		t.Error("a nil detection must be safe")
	}

	ai := cyclonedx.AIDetections{Models: []cyclonedx.AIModel{{Name: "gpt-4o"}}}
	if n := filterSuppressedAIDetections(&ai, nil); n != 0 || len(ai.Models) != 1 {
		t.Error("a nil set must drop nothing")
	}
}

func TestEvidenceSites(t *testing.T) {
	got := evidenceSites([]cyclonedx.AIEvidence{
		{Locator: "src/app.go:42"},
		{Locator: "README.md"},
		{Locator: "weird:notanumber"},
	})
	if len(got) != 3 {
		t.Fatalf("expected 3 sites, got %d", len(got))
	}
	if got[0].path != "src/app.go" || got[0].line != 42 {
		t.Errorf("expected src/app.go:42 to split, got %+v", got[0])
	}
	// No numeric suffix: the whole locator is the path and the line is unknown,
	// which leaves any rule line-range non-binding rather than excluding it.
	if got[1].path != "README.md" || got[1].line != 0 {
		t.Errorf("expected a bare path to keep line 0, got %+v", got[1])
	}
	if got[2].path != "weird:notanumber" || got[2].line != 0 {
		t.Errorf("a non-numeric suffix is part of the path, got %+v", got[2])
	}
}

// A file-anchored rule covers the sites it matches, not the whole component.
// Dropping the component outright would make the console's "This occurrence
// only" scope quietly hide occurrences elsewhere.
func TestComponentSuppression_PartialByFile(t *testing.T) {
	det := cyclonedx.CryptoDetections{
		Assets: []cyclonedx.CryptoAsset{{
			SPDXID: "RSA", Name: "RSA", Occurrences: 2,
			Evidence: []cyclonedx.CryptoEvidence{
				{Locator: "test/fixtures.go:4"},
				{Locator: "src/auth.go:99"},
			},
		}},
	}
	set := inventorySet(suppress.Rule{Category: "crypto", TargetValue: "RSA", FilePath: "test/fixtures.go"})

	if dropped := filterSuppressedCryptoDetections(&det, set); dropped != 0 {
		t.Fatalf("a partially-covered component must survive, dropped %d", dropped)
	}
	if len(det.Assets) != 1 {
		t.Fatalf("expected the component to survive, got %+v", det.Assets)
	}
	if len(det.Assets[0].Evidence) != 1 || det.Assets[0].Evidence[0].Locator != "src/auth.go:99" {
		t.Errorf("expected only the uncovered site to remain, got %+v", det.Assets[0].Evidence)
	}
	// The count must follow the evidence, or the report claims uses it no
	// longer shows.
	if det.Assets[0].Occurrences != 1 {
		t.Errorf("expected occurrences to drop to 1, got %d", det.Assets[0].Occurrences)
	}
}

// Once every site is covered, the component itself goes.
func TestComponentSuppression_AllSitesCoveredDropsComponent(t *testing.T) {
	det := cyclonedx.CryptoDetections{
		Assets: []cyclonedx.CryptoAsset{{
			SPDXID: "RSA", Name: "RSA",
			Evidence: []cyclonedx.CryptoEvidence{{Locator: "a.go:1"}, {Locator: "b.go:2"}},
		}},
	}
	set := inventorySet(
		suppress.Rule{Category: "crypto", TargetValue: "RSA", FilePath: "a.go"},
		suppress.Rule{Category: "crypto", TargetValue: "RSA", FilePath: "b.go"},
	)
	if dropped := filterSuppressedCryptoDetections(&det, set); dropped != 1 {
		t.Fatalf("expected the component to drop once every site is covered, dropped %d", dropped)
	}
	if len(det.Assets) != 0 {
		t.Errorf("expected no assets to remain, got %+v", det.Assets)
	}
}

// An unanchored (value-only) rule covers the component wherever it appears.
func TestComponentSuppression_ValueOnlyDropsWholeComponent(t *testing.T) {
	det := cyclonedx.CryptoDetections{
		Assets: []cyclonedx.CryptoAsset{{
			SPDXID: "RSA", Name: "RSA",
			Evidence: []cyclonedx.CryptoEvidence{{Locator: "a.go:1"}, {Locator: "b.go:2"}},
		}},
	}
	if dropped := filterSuppressedCryptoDetections(&det, inventorySet(
		suppress.Rule{Category: "crypto", TargetValue: "RSA"},
	)); dropped != 1 {
		t.Fatalf("a value-only rule should drop the whole component, dropped %d", dropped)
	}
}

// The same partial semantics apply to AI components.
func TestComponentSuppression_PartialByFile_AI(t *testing.T) {
	det := cyclonedx.AIDetections{
		Models: []cyclonedx.AIModel{{
			Name: "gpt-4o", Occurrences: 2,
			Evidence: []cyclonedx.AIEvidence{{Locator: "examples/demo.py:3"}, {Locator: "src/prod.py:10"}},
		}},
	}
	set := inventorySet(suppress.Rule{Category: "ai", TargetValue: "gpt-4o", FilePath: "examples/demo.py"})

	if dropped := filterSuppressedAIDetections(&det, set); dropped != 0 {
		t.Fatalf("a partially-covered model must survive, dropped %d", dropped)
	}
	if len(det.Models) != 1 || len(det.Models[0].Evidence) != 1 {
		t.Fatalf("expected one surviving site, got %+v", det.Models)
	}
	if det.Models[0].Evidence[0].Locator != "src/prod.py:10" {
		t.Errorf("expected the production use to survive, got %+v", det.Models[0].Evidence)
	}
}

// A line range narrows further still: same file, different line, still shown.
func TestComponentSuppression_PartialByLine(t *testing.T) {
	det := cyclonedx.CryptoDetections{
		Assets: []cyclonedx.CryptoAsset{{
			SPDXID: "MD5", Name: "MD5",
			Evidence: []cyclonedx.CryptoEvidence{{Locator: "a.go:5"}, {Locator: "a.go:50"}},
		}},
	}
	set := inventorySet(suppress.Rule{Category: "crypto", TargetValue: "MD5", FilePath: "a.go", LineRange: "1-10"})

	if dropped := filterSuppressedCryptoDetections(&det, set); dropped != 0 {
		t.Fatalf("expected the component to survive, dropped %d", dropped)
	}
	if len(det.Assets[0].Evidence) != 1 || det.Assets[0].Evidence[0].Locator != "a.go:50" {
		t.Errorf("expected only the in-range site to be covered, got %+v", det.Assets[0].Evidence)
	}
}

func TestAdjustOccurrences(t *testing.T) {
	ev := func(n int) []cyclonedx.AIEvidence { return make([]cyclonedx.AIEvidence, n) }

	if got := adjustOccurrences(5, ev(3), ev(3)); got != 5 {
		t.Errorf("nothing filtered should leave the count alone, got %d", got)
	}
	if got := adjustOccurrences(5, ev(3), ev(1)); got != 3 {
		t.Errorf("expected 5-2=3, got %d", got)
	}
	// Never below the evidence that remains, and never negative.
	if got := adjustOccurrences(2, ev(4), ev(2)); got != 2 {
		t.Errorf("expected a floor at the surviving evidence count, got %d", got)
	}
	if got := adjustOccurrences(0, ev(2), ev(1)); got != 0 {
		t.Errorf("an unset count should stay unset, got %d", got)
	}
}
