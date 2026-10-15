package repo

import "regexp"

var sha1Pattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

type Commit struct {
	SHA1 string
}

// isSha1 reports whether s looks like a commit id; sha1.Sum is not used here.
func isSha1(s string) bool { return @@sample:s[h]a1[P]at[t]er[n][.]M[a]tc[h]St[r]in[g]@@(s) }
