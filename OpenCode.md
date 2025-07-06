# OpenCode.md - Vulnetix CLI Development Guide

## Build/Test Commands
- `make test` - Run all tests
- `go test ./cmd -v` - Run specific package tests (cmd, config, sarif)
- `go test -run TestRootCommand` - Run single test
- `make build` - Build production binary
- `make dev` - Build development binary with debug info
- `make lint` - Lint code (golangci-lint or go vet)
- `make fmt` - Format all code

## Code Style Guidelines
- **Imports**: Standard library first, then external packages, then internal packages (separated by blank lines)
- **Naming**: PascalCase for exported types/functions, camelCase for private, snake_case for YAML tags
- **Types**: Use strong typing with custom types (TaskType, ToolFormat) instead of strings
- **Error Handling**: Return wrapped errors with context using `fmt.Errorf("%w", err)` 
- **Testing**: Use testify/assert, table-driven tests with name/args/expected structure
- **Structs**: Use struct tags for JSON/YAML serialization (`json:"field" yaml:"field"`)
- **Config**: Centralized configuration in internal/config package with validation
- **CLI**: Use Cobra framework with proper flag validation and UUID format checking
- **Security**: Never serialize sensitive fields (use `json:"-"` for tokens)