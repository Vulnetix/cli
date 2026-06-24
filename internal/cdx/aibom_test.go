package cdx

import (
	"bytes"
	"testing"
)

func sampleDetections() AIDetections {
	return AIDetections{
		CatalogVersion: "test-1",
		Tools: []AITool{{
			ID: "claude-code", Name: "Claude Code", Vendor: "Anthropic", Type: "cli-agent",
			Homepage: "https://www.anthropic.com/claude-code", Confidence: "high",
			ArtifactCounts: map[string]int{"agents": 2, "skills": 5},
			Evidence:       []AIEvidence{{Method: "file", Category: "instructions", Locator: "CLAUDE.md"}},
		}},
		Libraries: []AILibrary{{
			ID: "openai-python", Name: "openai", Provider: "OpenAI", Languages: []string{"python"},
			Purl: "pkg:pypi/openai", Confidence: "high",
			Evidence: []AIEvidence{{Method: "source", Category: "import", Locator: "main.py"}},
		}},
		Models: []AIModel{{
			Name: "gpt-9-zeta-2099", Provider: "OpenAI", Family: "GPT", ViaSDK: "openai-python",
			Task: "chat", Known: true, Occurrences: 3, Confidence: "high",
			Evidence: []AIEvidence{{Method: "source", Category: "model", Locator: "main.py:3", Snippet: "model=gpt-9-zeta-2099"}},
		}},
	}
}

func TestBuildAIBOMValidates(t *testing.T) {
	for _, spec := range []string{"1.6", "1.7"} {
		bom, err := BuildAIBOM(sampleDetections(), spec, nil)
		if err != nil {
			t.Fatalf("BuildAIBOM(%s): %v", spec, err)
		}
		// The write-time gate enforces schema validity — this is the key check
		// that the machine-learning-model components + modelCard are valid.
		data, err := bom.MarshalValidatedJSON()
		if err != nil {
			t.Fatalf("AIBOM (%s) failed schema validation: %v", spec, err)
		}
		if !bytes.Contains(data, []byte(`"machine-learning-model"`)) {
			t.Errorf("spec %s: expected a machine-learning-model component", spec)
		}
		if !bytes.Contains(data, []byte(`"modelCard"`)) {
			t.Errorf("spec %s: expected a modelCard", spec)
		}
	}
}

func TestBuildAIBOMStructure(t *testing.T) {
	bom, err := BuildAIBOM(sampleDetections(), "1.7", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(bom.Components) != 3 {
		t.Fatalf("want 3 components, got %d", len(bom.Components))
	}
	var model *Component
	for i := range bom.Components {
		if bom.Components[i].Type == "machine-learning-model" {
			model = &bom.Components[i]
		}
	}
	if model == nil {
		t.Fatal("no machine-learning-model component")
	}
	if model.ModelCard == nil || model.ModelCard.ModelParameters == nil {
		t.Fatal("model component missing modelCard/modelParameters")
	}
	if model.ModelCard.ModelParameters.ModelArchitecture != "gpt-9-zeta-2099" {
		t.Errorf("modelArchitecture = %q, want gpt-9-zeta-2099", model.ModelCard.ModelParameters.ModelArchitecture)
	}
	if model.Publisher != "OpenAI" {
		t.Errorf("model publisher = %q, want OpenAI", model.Publisher)
	}
	// Dependency graph should link the model under its SDK.
	if len(bom.Dependencies) == 0 {
		t.Error("expected a dependency graph")
	}
}
