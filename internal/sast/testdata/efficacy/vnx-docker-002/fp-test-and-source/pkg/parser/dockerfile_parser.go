package parser

import "strings"

// IsFrom reports whether a line is a FROM instruction.
func IsFrom(line string) bool {
	return strings.HasPrefix(strings.ToUpper(line), "FROM ")
}

const example = `
FROM ubuntu
`
