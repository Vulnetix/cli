package redact

import "strings"

func IsFineGrained(t string) bool { return strings.HasPrefix(t, "github_pat_") }
