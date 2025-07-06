package sarif

import (
	"fmt"
	"io"
	"strings"

	gosarif "github.com/owenrumney/go-sarif/v2/sarif"
)

// EnhancedValidator provides comprehensive SARIF validation using third-party library
type EnhancedValidator struct {
	validator *Validator
}

// NewEnhancedValidator creates a new enhanced SARIF validator
func NewEnhancedValidator() *EnhancedValidator {
	return &EnhancedValidator{
		validator: NewValidator(),
	}
}

// ValidationResult extends the basic validation result with enhanced information
type EnhancedValidationResult struct {
	*ValidationResult
	SchemaValid       bool     `json:"schemaValid"`
	SchemaErrors      []string `json:"schemaErrors,omitempty"`
	ThirdPartyLibrary string   `json:"thirdPartyLibrary"`
}

// ValidateFromReader validates a SARIF document from an io.Reader using both custom and third-party validation
func (ev *EnhancedValidator) ValidateFromReader(reader io.Reader) (*EnhancedValidationResult, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read SARIF data: %w", err)
	}

	return ev.ValidateFromBytes(data)
}

// ValidateFromBytes validates a SARIF document using both custom and go-sarif library validation
func (ev *EnhancedValidator) ValidateFromBytes(data []byte) (*EnhancedValidationResult, error) {
	// First run our custom validation
	customResult, err := ev.validator.ValidateFromBytes(data)
	if err != nil {
		return nil, fmt.Errorf("custom validation error: %w", err)
	}

	// Create enhanced result
	enhanced := &EnhancedValidationResult{
		ValidationResult:  customResult,
		ThirdPartyLibrary: "github.com/owenrumney/go-sarif/v2",
	}

	// Run third-party validation using go-sarif library
	enhanced.validateWithGoSarif(data)

	// Combine validation results
	enhanced.Valid = enhanced.Valid && enhanced.SchemaValid

	return enhanced, nil
}

// validateWithGoSarif performs validation using the go-sarif library
func (ev *EnhancedValidationResult) validateWithGoSarif(data []byte) {
	// Try to parse with go-sarif library
	report, err := gosarif.FromBytes(data)
	if err != nil {
		ev.SchemaValid = false
		ev.SchemaErrors = append(ev.SchemaErrors, fmt.Sprintf("go-sarif parsing error: %v", err))
		return
	}

	// Basic structural validation since Validate() method is not available
	if report == nil {
		ev.SchemaValid = false
		ev.SchemaErrors = append(ev.SchemaErrors, "go-sarif returned nil report")
		return
	}

	// Check basic structure
	if len(report.Runs) == 0 {
		ev.SchemaValid = false
		ev.SchemaErrors = append(ev.SchemaErrors, "go-sarif: report has no runs")
		return
	}

	// Check version
	if report.Version == "" {
		ev.SchemaValid = false
		ev.SchemaErrors = append(ev.SchemaErrors, "go-sarif: report has no version")
		return
	}

	// If we got here, go-sarif was able to parse it successfully
	ev.SchemaValid = true
}

// ValidateComprehensive runs all test cases and returns detailed results
func (ev *EnhancedValidator) ValidateComprehensive() *ComprehensiveTestResult {
	result := &ComprehensiveTestResult{
		TotalTests:    len(ComprehensiveSARIFTestCases),
		PassedTests:   0,
		FailedTests:   0,
		TestResults:   make([]SingleTestResult, 0),
		ValidatorInfo: "Enhanced validator with go-sarif library",
	}

	for _, testCase := range ComprehensiveSARIFTestCases {
		singleResult := ev.runSingleTest(testCase)
		result.TestResults = append(result.TestResults, singleResult)

		if singleResult.TestPassed {
			result.PassedTests++
		} else {
			result.FailedTests++
		}
	}

	return result
}

// runSingleTest executes a single test case
func (ev *EnhancedValidator) runSingleTest(testCase struct {
	Name        string
	SARIF       string
	ShouldPass  bool
	Version     string
	Description string
}) SingleTestResult {
	validation, err := ev.ValidateFromBytes([]byte(testCase.SARIF))
	
	result := SingleTestResult{
		TestName:    testCase.Name,
		Description: testCase.Description,
		Expected:    testCase.ShouldPass,
		SARIFValid:  false,
		Errors:      make([]string, 0),
	}

	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Validation error: %v", err))
		result.TestPassed = !testCase.ShouldPass // Test passes if we expected it to fail
		return result
	}

	result.SARIFValid = validation.Valid && validation.SchemaValid
	result.TestPassed = result.SARIFValid == testCase.ShouldPass
	
	// Collect all errors
	if validation.Errors != nil {
		result.Errors = append(result.Errors, validation.Errors...)
	}
	if validation.SchemaErrors != nil {
		result.Errors = append(result.Errors, validation.SchemaErrors...)
	}

	// Add version info if available
	if validation.Version != "" {
		result.Version = validation.Version
	}

	return result
}

// ComprehensiveTestResult contains results from running all test cases
type ComprehensiveTestResult struct {
	TotalTests    int                `json:"totalTests"`
	PassedTests   int                `json:"passedTests"`
	FailedTests   int                `json:"failedTests"`
	TestResults   []SingleTestResult `json:"testResults"`
	ValidatorInfo string             `json:"validatorInfo"`
}

// SingleTestResult contains the result of a single test case
type SingleTestResult struct {
	TestName    string   `json:"testName"`
	Description string   `json:"description"`
	Expected    bool     `json:"expected"`
	SARIFValid  bool     `json:"sarifValid"`
	TestPassed  bool     `json:"testPassed"`
	Version     string   `json:"version,omitempty"`
	Errors      []string `json:"errors,omitempty"`
}

// PrintSummary prints a summary of the comprehensive test results
func (ctr *ComprehensiveTestResult) PrintSummary() {
	fmt.Printf("🧪 SARIF Validation Test Summary\n")
	fmt.Printf("=================================\n")
	fmt.Printf("Total Tests: %d\n", ctr.TotalTests)
	fmt.Printf("✅ Passed: %d\n", ctr.PassedTests)
	fmt.Printf("❌ Failed: %d\n", ctr.FailedTests)
	fmt.Printf("📊 Success Rate: %.1f%%\n", float64(ctr.PassedTests)/float64(ctr.TotalTests)*100)
	fmt.Printf("🔧 Validator: %s\n", ctr.ValidatorInfo)
	fmt.Printf("\n")

	if ctr.FailedTests > 0 {
		fmt.Printf("❌ Failed Tests:\n")
		for _, result := range ctr.TestResults {
			if !result.TestPassed {
				fmt.Printf("  - %s: %s\n", result.TestName, result.Description)
				if len(result.Errors) > 0 {
					fmt.Printf("    Errors: %s\n", strings.Join(result.Errors, "; "))
				}
			}
		}
	}
}

// GetFailedTests returns only the failed test results
func (ctr *ComprehensiveTestResult) GetFailedTests() []SingleTestResult {
	failed := make([]SingleTestResult, 0)
	for _, result := range ctr.TestResults {
		if !result.TestPassed {
			failed = append(failed, result)
		}
	}
	return failed
}