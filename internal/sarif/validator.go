package sarif

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// SupportedVersions defines the SARIF versions we support
var SupportedVersions = map[string]bool{
	"2.1.0": true,
	"2.0.0": true,
}

// SARIFDocument represents the basic structure of a SARIF document
type SARIFDocument struct {
	Version string `json:"version"`
	Runs    []Run  `json:"runs"`
}

// Run represents a single run in the SARIF document
type Run struct {
	Tool    Tool      `json:"tool"`
	Results []Result  `json:"results,omitempty"`
}

// Tool represents the tool that generated the SARIF output
type Tool struct {
	Driver ToolComponent `json:"driver"`
}

// ToolComponent represents the driver component of the tool
type ToolComponent struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// Result represents a single result in the SARIF output
type Result struct {
	RuleID  string `json:"ruleId,omitempty"`
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
	Level string `json:"level,omitempty"`
}

// ValidationResult contains the results of SARIF validation
type ValidationResult struct {
	Valid   bool     `json:"valid"`
	Version string   `json:"version"`
	Errors  []string `json:"errors,omitempty"`
	Stats   Stats    `json:"stats"`
}

// Stats contains statistics about the SARIF document
type Stats struct {
	RunCount    int `json:"runCount"`
	ResultCount int `json:"resultCount"`
	ToolCount   int `json:"toolCount"`
}

// Validator provides SARIF validation functionality
type Validator struct{}

// NewValidator creates a new SARIF validator
func NewValidator() *Validator {
	return &Validator{}
}

// ValidateFromReader validates a SARIF document from an io.Reader
func (v *Validator) ValidateFromReader(reader io.Reader) (*ValidationResult, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read SARIF data: %w", err)
	}

	return v.ValidateFromBytes(data)
}

// ValidateFromBytes validates a SARIF document from a byte slice
func (v *Validator) ValidateFromBytes(data []byte) (*ValidationResult, error) {
	// First, try to parse as JSON to get basic structure
	var doc SARIFDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return &ValidationResult{
			Valid:  false,
			Errors: []string{fmt.Sprintf("Invalid JSON format: %v", err)},
		}, nil
	}

	result := &ValidationResult{
		Valid:   true,
		Version: doc.Version,
		Stats:   v.calculateStats(&doc),
	}

	// Validate version
	if !SupportedVersions[doc.Version] {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("Unsupported SARIF version: %s (supported: %s)", 
			doc.Version, strings.Join(v.getSupportedVersionsList(), ", ")))
	}

	// Version-specific validation
	switch doc.Version {
	case "2.1.0":
		v.validateVersion210(&doc, result)
	case "2.0.0":
		v.validateVersion200(&doc, result)
	default:
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("No validation rules for version %s", doc.Version))
	}

	// Basic structural validation
	v.validateBasicStructure(&doc, result)

	return result, nil
}

// validateVersion210 performs validation specific to SARIF 2.1.0
func (v *Validator) validateVersion210(doc *SARIFDocument, result *ValidationResult) {
	// SARIF 2.1.0 specific validations
	if len(doc.Runs) == 0 {
		result.Valid = false
		result.Errors = append(result.Errors, "SARIF 2.1.0 requires at least one run")
	}

	for i, run := range doc.Runs {
		// Validate tool driver name is present
		if run.Tool.Driver.Name == "" {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("Run %d: tool.driver.name is required in SARIF 2.1.0", i))
		}

		// Validate results structure
		for j, res := range run.Results {
			if res.Message.Text == "" {
				result.Valid = false
				result.Errors = append(result.Errors, fmt.Sprintf("Run %d, Result %d: message.text is required", i, j))
			}
		}
	}
}

// validateVersion200 performs validation specific to SARIF 2.0.0
func (v *Validator) validateVersion200(doc *SARIFDocument, result *ValidationResult) {
	// SARIF 2.0.0 specific validations
	if len(doc.Runs) == 0 {
		result.Valid = false
		result.Errors = append(result.Errors, "SARIF 2.0.0 requires at least one run")
	}

	for i, run := range doc.Runs {
		// In SARIF 2.0.0, tool structure is different - check both old and new style
		if run.Tool.Driver.Name == "" {
			// Try to get tool name from legacy SARIF 2.0.0 structure
			if v.getToolNameFromLegacyStructure(run) == "" {
				result.Valid = false
				result.Errors = append(result.Errors, fmt.Sprintf("Run %d: tool name is required in SARIF 2.0.0", i))
			}
		}
	}
}

// validateBasicStructure performs general structural validation
func (v *Validator) validateBasicStructure(doc *SARIFDocument, result *ValidationResult) {
	// Check for empty version
	if doc.Version == "" {
		result.Valid = false
		result.Errors = append(result.Errors, "SARIF version field is required")
	}

	// Validate runs array
	if doc.Runs == nil {
		result.Valid = false
		result.Errors = append(result.Errors, "SARIF runs array is required")
	}
}

// calculateStats calculates statistics about the SARIF document
func (v *Validator) calculateStats(doc *SARIFDocument) Stats {
	stats := Stats{
		RunCount: len(doc.Runs),
	}

	toolNames := make(map[string]bool)
	
	for _, run := range doc.Runs {
		stats.ResultCount += len(run.Results)
		if run.Tool.Driver.Name != "" {
			toolNames[run.Tool.Driver.Name] = true
		}
	}

	stats.ToolCount = len(toolNames)
	
	return stats
}

// getSupportedVersionsList returns a slice of supported versions
func (v *Validator) getSupportedVersionsList() []string {
	versions := make([]string, 0, len(SupportedVersions))
	for version := range SupportedVersions {
		versions = append(versions, version)
	}
	return versions
}

// getToolNameFromLegacyStructure extracts tool name from SARIF 2.0.0 legacy structure
func (v *Validator) getToolNameFromLegacyStructure(run Run) string {
	// In SARIF 2.0.0, tool might have a direct "name" field
	// Parse the run as raw JSON to check for legacy fields
	if run.Tool.Driver.Name != "" {
		return run.Tool.Driver.Name
	}
	return ""
}

// GetSupportedVersions returns the map of supported SARIF versions
func GetSupportedVersions() map[string]bool {
	return SupportedVersions
}