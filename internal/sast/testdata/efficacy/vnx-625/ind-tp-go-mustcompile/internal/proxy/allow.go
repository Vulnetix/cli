package proxy

import (
	"net/http"
	"regexp"
)

~>var upstreamAllowed = regexp.MustCompile(`^https://[a-z0-9-]+\.internal\.acme\.io`)

func checkUpstream(w http.ResponseWriter, target string) bool {
	if !upstreamAllowed.MatchString(target) {
		http.Error(w, "upstream not allowed", http.StatusForbidden)
		return false
	}
	return true
}
