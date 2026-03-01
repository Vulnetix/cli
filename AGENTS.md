# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Vulnetix is a CLI tool for automated vulnerability management that focuses on remediation over discovery. It's designed as both a standalone Go CLI and a GitHub Action. The tool supports multiple operational modes including vulnerability scanning and automated triage.

## Architecture

This is a Go-based CLI application with the following key components:

- **Main CLI entry point**: `main.go` - Simple entry point that delegates to the cmd package
- **Command structure**: `cmd/root.go` - Uses Cobra CLI framework with comprehensive flag handling
- **Configuration management**: `internal/config/config.go` - Handles all configuration, GitHub context, and task validation
- **Task types**: Two main operations (info, triage) with specialized configurations
- **GitHub integration**: Deep integration with GitHub Actions environment variables and artifact handling

## Build and Development Commands

Use the Makefile for all development tasks:

```bash
# Build for development
make dev

# Build production binary
make build

# Run tests
make test

# Format code
make fmt

# Lint code (uses golangci-lint if available, falls back to go vet)
make lint

# Build for all platforms
make build-all

# Clean build artifacts
make clean

# Download and tidy dependencies
make deps

# Run with test UUID
make run
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
make test
```

## Important Development Notes

- The CLI requires a valid UUID for `--org-id` parameter
- Version is injected at build time via ldflags
- GitHub context is automatically loaded from environment variables
- Tool configurations use YAML format for complex artifact specifications
- The application is designed primarily for CI/CD environments, particularly GitHub Actions