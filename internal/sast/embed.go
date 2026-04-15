package sast

import "embed"

// DefaultRulesFS holds the built-in .rego rule files compiled into the binary.
// The rules/ directory is relative to this file (internal/sast/rules/).
//
//go:embed rules
var DefaultRulesFS embed.FS
