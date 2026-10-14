package redact

import "strings"

var prefixes = []string{"ghp_", "gho_", "ghs_", "github_pat_", "glpat-"}

func IsToken(s string) bool { return strings.HasPrefix(s, "ghp_") || strings.HasPrefix(s, "glpat-") }
