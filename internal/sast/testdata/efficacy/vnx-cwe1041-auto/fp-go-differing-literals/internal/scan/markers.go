package scan

import "strings"

// The two literals differ only in a space: "extra ==" and "extra==" are two
// spellings of a PEP 508 marker, not one operand written twice.
func optionalOnly(deps []string) []string {
	var out []string
	for _, dep := range deps {
		if strings.Contains(dep, "; ") {
			marker := dep[strings.Index(dep, "; ")+2:]
			if strings.Contains(marker, "extra ==") || strings.Contains(marker, "extra==") {
				continue
			}
		}
		out = append(out, dep)
	}
	return out
}

// Same call, different literal: two distinct tests.
func isWindows(goos string) bool {
	return strings.HasPrefix(goos, "win") || strings.HasPrefix(goos, "Win")
}
