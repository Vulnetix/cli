package sarif

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestComprehensiveSARIFValidation(t *testing.T) {
	validator := NewEnhancedValidator()
	
	// Run comprehensive test suite
	results := validator.ValidateComprehensive()
	
	// Print detailed results
	results.PrintSummary()
	
	// Assert that we have reasonable test coverage
	if results.TotalTests < 10 {
		t.Errorf("Expected at least 10 test cases, got %d", results.TotalTests)
	}
	
	// Check individual test cases
	for _, result := range results.TestResults {
		t.Run(result.TestName, func(t *testing.T) {
			if !result.TestPassed {
				t.Errorf("Test failed: %s - %s", result.Description, result.Errors)
			}
		})
	}
	
	// Ensure we have some passing tests
	if results.PassedTests == 0 {
		t.Error("No tests passed - validation logic may be broken")
	}
	
	// Check that our test framework is working correctly
	if results.TotalTests != results.PassedTests+results.FailedTests {
		t.Errorf("Test count mismatch: total=%d, passed=%d, failed=%d", 
			results.TotalTests, results.PassedTests, results.FailedTests)
	}
}

func TestEnhancedValidatorWithValidSARIF(t *testing.T) {
	validator := NewEnhancedValidator()
	
	validSARIF := `{
		"version": "2.1.0",
		"runs": [
			{
				"tool": {
					"driver": {
						"name": "TestTool",
						"version": "1.0.0",
						"informationUri": "https://example.com"
					}
				},
				"results": [
					{
						"message": {
							"text": "Test finding"
						},
						"ruleId": "test-rule",
						"level": "error",
						"locations": [
							{
								"physicalLocation": {
									"artifactLocation": {
										"uri": "test.js"
									},
									"region": {
										"startLine": 1,
										"startColumn": 1
									}
								}
							}
						]
					}
				]
			}
		]
	}`
	
	result, err := validator.ValidateFromBytes([]byte(validSARIF))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	if !result.Valid {
		t.Errorf("Expected valid SARIF, but custom validation failed: %v", result.Errors)
	}
	
	if !result.SchemaValid {
		t.Errorf("Expected schema valid SARIF, but third-party validation failed: %v", result.SchemaErrors)
	}
	
	if result.Version != "2.1.0" {
		t.Errorf("Expected version 2.1.0, got %s", result.Version)
	}
	
	if result.ThirdPartyLibrary != "github.com/owenrumney/go-sarif/v2" {
		t.Errorf("Expected third-party library info, got %s", result.ThirdPartyLibrary)
	}
}

func TestEnhancedValidatorWithInvalidSARIF(t *testing.T) {
	validator := NewEnhancedValidator()
	
	tests := []struct {
		name          string
		sarif         string
		expectValid   bool
		expectSchema  bool
	}{
		{
			name: "Invalid JSON",
			sarif: `{
				"version": "2.1.0"
				"runs": []
			}`,
			expectValid:  false,
			expectSchema: false,
		},
		{
			name: "Missing required field",
			sarif: `{
				"version": "2.1.0",
				"runs": [
					{
						"tool": {
							"driver": {}
						}
					}
				]
			}`,
			expectValid:  false,
			expectSchema: true,
		},
		{
			name: "Empty runs",
			sarif: `{
				"version": "2.1.0",
				"runs": []
			}`,
			expectValid:  false,
			expectSchema: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := validator.ValidateFromBytes([]byte(tt.sarif))
			if err != nil && tt.expectValid {
				t.Fatalf("Unexpected error for valid case: %v", err)
			}
			
			if result != nil {
				if result.Valid != tt.expectValid {
					t.Errorf("Expected custom validation %t, got %t", tt.expectValid, result.Valid)
				}
				
				if result.SchemaValid != tt.expectSchema {
					t.Errorf("Expected schema validation %t, got %t", tt.expectSchema, result.SchemaValid)
				}
			}
		})
	}
}

func TestSARIFVersionSupport(t *testing.T) {
	validator := NewEnhancedValidator()
	
	versions := []struct {
		version string
		valid   bool
	}{
		{"2.1.0", true},
		{"2.0.0", true},
		{"1.0.0", false},
		{"3.0.0", false},
		{"", false},
	}
	
	for _, v := range versions {
		t.Run("Version_"+v.version, func(t *testing.T) {
			sarif := `{
				"version": "` + v.version + `",
				"runs": [
					{
						"tool": {
							"driver": {
								"name": "TestTool"
							}
						}
					}
				]
			}`
			
			if v.version == "" {
				sarif = `{
					"runs": [
						{
							"tool": {
								"driver": {
									"name": "TestTool"
								}
							}
						}
					]
				}`
			}
			
			result, err := validator.ValidateFromBytes([]byte(sarif))
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			
			if result.Valid != v.valid {
				t.Errorf("Version %s: expected validity %t, got %t", v.version, v.valid, result.Valid)
			}
		})
	}
}

func TestLargeSARIFHandling(t *testing.T) {
	validator := NewEnhancedValidator()
	
	// Create a large SARIF with many results
	type location struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine   int `json:"startLine"`
				StartColumn int `json:"startColumn"`
			} `json:"region"`
		} `json:"physicalLocation"`
	}
	
	type result struct {
		Message struct {
			Text string `json:"text"`
		} `json:"message"`
		RuleID    string     `json:"ruleId"`
		Level     string     `json:"level"`
		Locations []location `json:"locations"`
	}
	
	type run struct {
		Tool struct {
			Driver struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"driver"`
		} `json:"tool"`
		Results []result `json:"results"`
	}
	
	type sarifDoc struct {
		Version string `json:"version"`
		Runs    []run  `json:"runs"`
	}
	
	// Create SARIF with 1000 results
	doc := sarifDoc{
		Version: "2.1.0",
		Runs: []run{
			{
				Tool: struct {
					Driver struct {
						Name    string `json:"name"`
						Version string `json:"version"`
					} `json:"driver"`
				}{
					Driver: struct {
						Name    string `json:"name"`
						Version string `json:"version"`
					}{
						Name:    "LargeTool",
						Version: "1.0.0",
					},
				},
				Results: make([]result, 1000),
			},
		},
	}
	
	// Fill in results
	for i := 0; i < 1000; i++ {
		doc.Runs[0].Results[i] = result{
			Message: struct {
				Text string `json:"text"`
			}{
				Text: fmt.Sprintf("Finding %d", i),
			},
			RuleID: fmt.Sprintf("rule-%d", i),
			Level:  "info",
			Locations: []location{
				{
					PhysicalLocation: struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine   int `json:"startLine"`
							StartColumn int `json:"startColumn"`
						} `json:"region"`
					}{
						ArtifactLocation: struct {
							URI string `json:"uri"`
						}{
							URI: fmt.Sprintf("file%d.js", i%100),
						},
						Region: struct {
							StartLine   int `json:"startLine"`
							StartColumn int `json:"startColumn"`
						}{
							StartLine:   i + 1,
							StartColumn: 1,
						},
					},
				},
			},
		}
	}
	
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("Failed to marshal large SARIF: %v", err)
	}
	
	validationResult, err := validator.ValidateFromBytes(data)
	if err != nil {
		t.Fatalf("Unexpected error validating large SARIF: %v", err)
	}
	
	if !validationResult.Valid {
		t.Errorf("Large SARIF should be valid, but got errors: %v", validationResult.Errors)
	}
	
	if validationResult.Stats.ResultCount != 1000 {
		t.Errorf("Expected 1000 results, got %d", validationResult.Stats.ResultCount)
	}
	
	t.Logf("Successfully validated large SARIF with %d results", validationResult.Stats.ResultCount)
}