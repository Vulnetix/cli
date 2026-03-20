# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Vulnetix is a CLI tool for automated vulnerability management that focuses on remediation over discovery. It's designed as both a standalone Go CLI and a GitHub Action. The tool supports multiple operational modes including authentication healthchecks, artifact uploads, and vulnerability database queries.

## Architecture

This is a Go-based CLI application with the following key components:

- **Main CLI entry point**: `main.go` - Simple entry point that delegates to the cmd package
- **Command structure**: `cmd/root.go` - Uses Cobra CLI framework with comprehensive flag handling
- **Configuration management**: `internal/config/config.go` - Handles all configuration, GitHub context, and task validation
- **Task types**: The root command runs an info healthcheck; subcommands provide auth, upload, gha, scan, and vdb operations
- **GitHub integration**: Deep integration with GitHub Actions environment variables and artifact handling

### VDB Subcommands

The `vdb` command queries the Vulnetix Vulnerability Database API. Commands support `-V v1` (default) or `-V v2` for API version selection, and `-o json` for JSON output.

**V1+V2 commands**: `vuln`, `exploits`, `info`, `gcve`, `product`, `packages`, `ecosystems`, `sources`, `summary`, `identifiers`, `eol`, `purl`
**V2-only commands** (require `-V v2`): `scorecard` (+ `search` subcommand), `timeline`, `affected`, `kev`, `advisories`, `workarounds`, `cwe` (+ `guidance`), `remediation` (+ `plan`), `cloud-locators`, `fixes` (V2 fetches registry/distributions/source in parallel)
**Utility**: `status`, `cache` (+ `clear`)

## Build and Development Commands

Use the justfile for all development tasks:

```bash
# Build for development
just dev

# Build production binary
just build

# Run tests
just test

# Format code
just fmt

# Lint code (uses golangci-lint if available, falls back to go vet)
just lint

# Build for all platforms
just build-all

# Clean build artifacts
just clean

# Download and tidy dependencies
just deps

# Run with test UUID
just run
```

## Key Configuration Patterns

The application uses a centralized configuration system (`VulnetixConfig`) that:

- Validates all inputs including UUID format for org-id
- Loads complete GitHub context from environment variables
- Supports YAML parsing for complex inputs (tools, tags)
- Provides artifact naming conventions for GitHub Actions workflows
- Handles different task types with specific validation rules

## Testing

Tests are minimal currently (`cmd/root_test.go`). Run with:
```bash
just test
```

## Important Development Notes

- The CLI requires a valid UUID for `--org-id` parameter
- Version is injected at build time via ldflags
- GitHub context is automatically loaded from environment variables
- Tool configurations use YAML format for complex artifact specifications
- The application is designed primarily for CI/CD environments, particularly GitHub Actions