package lexer

import "strings"

var separators = []string{";", "&&", "||", "|"}

func Split(cmd string) []string {
	parts := []string{cmd}
	for _, sep := range separators {
		var next []string
		for _, p := range parts {
			next = append(next, strings.Split(p, sep)...)
		}
		parts = next
	}
	return parts
}
