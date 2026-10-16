package gh

import "strings"

func isFineGrained(t string) bool {
	return strings.HasPrefix(t, "github_pat_")
}

const short = "github_pat_11ABCDEFG0abcdefghijkl_abcdef"
const ph = "github_pat_xxxxxxxxxxxxxxxxxxxxxx_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
