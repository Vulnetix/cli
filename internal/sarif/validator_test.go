package sarif

import (
	"strings"
	"testing"
)

func TestValidateFromBytes(t *testing.T) {
	validator := NewValidator()

	tests := []struct {
		name     string
		sarif    string
		expected bool
		errors   int
	}{
		{
			name: "Valid SARIF 2.1.0",
			sarif: `{
				"version": "2.1.0",
				"runs": [
					{
						"tool": {
							"driver": {
								"name": "test-tool",
								"version": "1.0.0"
							}
						},
						"results": [
							{
								"message": {
									"text": "Test finding"
								},
								"ruleId": "test-rule",
								"level": "error"
							}
						]
					}
				]
			}`,
			expected: true,
			errors:   0,
		},
		{
			name: "Invalid JSON",
			sarif: `{
				"version": "2.1.0"
				"runs": []
			}`,
			expected: false,
			errors:   1,
		},
		{
			name: "Missing version",
			sarif: `{
				"runs": []
			}`,
			expected: false,
			errors:   3,
		},
		{
			name: "Unsupported version",
			sarif: `{
				"version": "3.0.0",
				"runs": []
			}`,
			expected: false,
			errors:   2,
		},
		{
			name: "Missing runs",
			sarif: `{
				"version": "2.1.0"
			}`,
			expected: false,
			errors:   2,
		},
		{
			name: "Empty runs array",
			sarif: `{
				"version": "2.1.0",
				"runs": []
			}`,
			expected: false,
			errors:   1,
		},
		{
			name: "Missing tool driver name",
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
			expected: false,
			errors:   1,
		},
		{
			name: "Missing message text",
			sarif: `{
				"version": "2.1.0",
				"runs": [
					{
						"tool": {
							"driver": {
								"name": "test-tool"
							}
						},
						"results": [
							{
								"message": {}
							}
						]
					}
				]
			}`,
			expected: false,
			errors:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := validator.ValidateFromBytes([]byte(tt.sarif))
			
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if result.Valid != tt.expected {
				t.Errorf("Expected valid=%t, got valid=%t", tt.expected, result.Valid)
			}

			if len(result.Errors) != tt.errors {
				t.Errorf("Expected %d errors, got %d: %v", tt.errors, len(result.Errors), result.Errors)
			}
		})
	}
}

func TestValidateFromReader(t *testing.T) {
	validator := NewValidator()
	
	validSARIF := `{
		"version": "2.1.0",
		"runs": [
			{
				"tool": {
					"driver": {
						"name": "test-tool"
					}
				}
			}
		]
	}`

	reader := strings.NewReader(validSARIF)
	result, err := validator.ValidateFromReader(reader)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !result.Valid {
		t.Errorf("Expected valid SARIF, got errors: %v", result.Errors)
	}

	if result.Version != "2.1.0" {
		t.Errorf("Expected version 2.1.0, got %s", result.Version)
	}
}

func TestGetSupportedVersions(t *testing.T) {
	versions := GetSupportedVersions()
	
	expectedVersions := []string{"2.1.0", "2.0.0"}
	
	for _, expectedVersion := range expectedVersions {
		if !versions[expectedVersion] {
			t.Errorf("Expected version %s to be supported", expectedVersion)
		}
	}
}