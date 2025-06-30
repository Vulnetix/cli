# Unit Test Plan for Vulnetix

## Overview

This document outlines a comprehensive plan to achieve 100% unit test coverage for the Vulnetix CLI project. The plan focuses on coverage reporting as the key metric while maintaining the principle of not modifying the existing production code.

## Current State Analysis

### Test Coverage Status
- **Current Coverage**: 21.7% (cmd package only)
- **Tested Functions**: 2 out of 12 identified functions (partial coverage)
- **Missing Test Files**: 4 test files needed
- **Failing Tests**: 2 out of 4 existing tests are failing

### Identified Gaps
1. **Zero coverage** in `internal/config` package
2. **No integration tests** for main package
3. **Incomplete coverage** of cmd package business logic
4. **Missing test infrastructure** for environment variable mocking

## Testing Strategy

### Principles
1. **No production code modification** - All tests must work with existing code as-is
2. **Coverage-driven development** - Target 90%+ coverage for all packages
3. **Dependency injection through testing** - Use test-specific environment setup
4. **Comprehensive error path testing** - Test all error conditions and edge cases

### Test Organization
```
├── main_test.go (integration tests)
├── cmd/
│   ├── root_test.go (expand existing)
│   ├── parsetools_test.go (new)
│   └── command_integration_test.go (new)
└── internal/config/
    ├── config_test.go (new)
    ├── validation_test.go (new)
    └── github_context_test.go (new)
```

## Implementation Plan

### Phase 1: Test Infrastructure Setup (Complete)

#### 1.1 Coverage Tooling (Complete)
- Set up `go test -cover` reporting
- Configure coverage threshold enforcement
- Add coverage HTML report generation
- Integrate coverage into Makefile

#### 1.2 Test Utilities (Complete)
- Create environment variable mock utilities
- Set up test fixtures for complex configurations
- Create helper functions for common test patterns

### Phase 2: Core Business Logic Tests (High Priority) (Complete)

#### 2.1 Config Package Validation Functions (Complete)
**Target: internal/config/validation_test.go**

```go
// Test functions:
// - ValidateTask() - All task types and error cases
// - ValidateReleaseReadiness() - All validation paths
// - IsReleaseTask() - Boolean logic validation
```

**Test Cases:**
- Valid task types: "scan", "release", "report", "triage"
- Invalid task types and error messages
- Empty/nil inputs
- Release readiness with missing branches
- Release readiness with missing GitHub context
- Release readiness with valid configuration

#### 2.2 Config Package Parsing Functions (Complete)
**Target: internal/config/config_test.go**

```go
// Test functions:
// - ParseTags() - String parsing and edge cases
// - GenerateArtifactNamingConvention() - Pattern generation
// - GetWorkflowRunContext() - Context mapping
// - GetSiblingJobsContext() - Context mapping
// - GetReleaseArtifactPattern() - Pattern generation
```

**Test Cases:**
- Valid YAML tag arrays
- Malformed tag strings
- Empty and nil inputs
- Special characters in artifact names
- Repository names with slashes
- Context mapping with missing fields

#### 2.3 GitHub Context Integration (Complete)
**Target: internal/config/github_context_test.go**

```go
// Test functions:
// - LoadGitHubContext() - Environment variable loading
// - getEnv() - Environment variable wrapper
```

**Test Cases:**
- Complete GitHub environment simulation
- Partial environment variables
- Missing environment variables
- Environment variable precedence

### Phase 3: Command Layer Tests (Medium Priority)

#### 3.1 Enhanced Root Command Tests
**Target: cmd/root_test.go (expand existing)**

```go
// Fix existing failing tests and add:
// - All task execution paths
// - Configuration validation integration
// - Error handling scenarios
// - Flag parsing and validation
```

**Test Cases:**
- Fix current failing UUID and flag tests
- Test all task types (scan, release, report, triage)
- Configuration printing and validation
- GitHub context integration
- Error path testing for all validation steps

#### 3.2 Tool Parsing Tests
**Target: cmd/parsetools_test.go**

```go
// Test functions:
// - parseTools() - YAML parsing and error handling
```

**Test Cases:**
- Valid YAML tool configurations
- Invalid YAML syntax
- Empty tool configurations
- Complex nested tool structures
- Malformed tool formats

#### 3.3 Command Integration Tests
**Target: cmd/command_integration_test.go**

```go
// Test functions:
// - Execute() - End-to-end command execution
// - Command flag combinations
// - Environment-dependent behaviors
```

### Phase 4: Integration and Main Package Tests (Low Priority)

#### 4.1 Main Package Integration Tests
**Target: main_test.go**

```go
// Test functions:
// - main() - Integration testing using subprocess pattern
```

**Test Cases:**
- Successful execution scenarios
- Error exit code testing
- Command line argument passing

### Phase 5: Coverage Optimization and Edge Cases

#### 5.1 Edge Case Testing
- Empty string inputs
- Very long input strings
- Unicode and special characters
- Concurrent execution scenarios
- Resource exhaustion scenarios

#### 5.2 Error Path Completeness
- All error return paths tested
- Panic recovery testing
- Invalid state handling

## Coverage Targets

### Package-Level Coverage Goals
- **main package**: 80% (limited due to integration nature)
- **cmd package**: 95% (comprehensive business logic coverage)
- **internal/config package**: 95% (comprehensive validation and parsing)

### Overall Project Coverage Goal
- **Target**: 90% overall coverage
- **Minimum Acceptable**: 85% overall coverage
- **Critical Functions**: 100% coverage for validation and parsing functions

## Testing Tools and Dependencies

### Required Test Dependencies
```go
// Test dependencies to add to go.mod:
// - github.com/stretchr/testify/assert
// - github.com/stretchr/testify/require
// - github.com/stretchr/testify/mock (if needed for interfaces)
```

### Environment Mocking Strategy
- Use `t.Setenv()` for environment variable testing
- Create test-specific GitHub context fixtures
- Mock external dependencies without modifying production code

## Makefile Integration

### New Make Targets
```makefile
# Coverage reporting
test-coverage:
	go test -v -cover ./...

# Coverage with HTML report
test-coverage-html:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Coverage threshold enforcement
test-coverage-check:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//' | awk '{if ($1 < 90) exit 1}'

# Comprehensive test suite
test-all: test test-coverage-check
```

## Implementation Timeline

### Week 1: Infrastructure and Config Package
- Set up coverage tooling
- Implement all config package tests
- Achieve 95% coverage for internal/config

### Week 2: Command Package Enhancement
- Fix existing failing tests
- Implement comprehensive cmd package tests
- Achieve 95% coverage for cmd package

### Week 3: Integration and Optimization
- Implement main package integration tests
- Add edge case testing
- Optimize coverage to meet 90% overall target

### Week 4: Documentation and CI Integration
- Document testing patterns
- Integrate coverage checks into CI/CD
- Create coverage reporting dashboard

## Success Metrics

### Primary Metrics
1. **Overall Coverage**: ≥90%
2. **Package Coverage**: ≥95% for cmd and config packages
3. **Test Reliability**: 100% test pass rate
4. **Coverage Trend**: Maintained or improved with new code

### Secondary Metrics
1. **Test Execution Time**: <10 seconds for full test suite
2. **Test Maintainability**: Clear, readable test code
3. **Error Coverage**: All error paths tested
4. **Documentation**: All test patterns documented

## Risk Mitigation

### Potential Challenges
1. **Environment Dependencies**: GitHub context mocking complexity
2. **Existing Test Failures**: Current tests need fixing
3. **Complex YAML Parsing**: Tool configuration parsing edge cases
4. **Integration Testing**: Main function testing complexity

### Mitigation Strategies
1. **Comprehensive Environment Mocking**: Use structured test fixtures
2. **Incremental Test Development**: Fix existing tests first
3. **Extensive Input Validation Testing**: Cover all parsing edge cases
4. **Subprocess Testing Pattern**: Use Go's subprocess testing for main()

## Conclusion

This plan provides a comprehensive approach to achieving 100% unit test coverage for the Vulnetix CLI project. By focusing on coverage reporting as the key metric and maintaining the principle of not modifying existing production code, we can ensure robust test coverage while preserving the integrity of the current codebase.

The phased approach allows for systematic implementation while maintaining development velocity. The emphasis on coverage-driven development ensures that all critical business logic is thoroughly tested, providing confidence in the reliability and maintainability of the Vulnetix CLI tool.