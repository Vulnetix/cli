package cors

import (
	"net/http"
	"regexp"
)

var trustedOrigin = regexp.MustCompile(`^https://([a-z0-9-]+\.)*example\.com$`)

func Allow(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if trustedOrigin.MatchString(origin) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
}
