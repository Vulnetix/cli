package cors

import (
	"net/http"
	"strings"
)

var allowedOrigins = map[string]bool{
	"https://acme.com":     true,
	"https://app.acme.com": true,
}

func Allow(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if allowedOrigins[origin] || strings.HasSuffix(origin, ".acme.com") {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
}
