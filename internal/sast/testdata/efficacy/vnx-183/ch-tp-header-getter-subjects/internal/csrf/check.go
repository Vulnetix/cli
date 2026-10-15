package csrf

import (
	"net/http"
	"strings"
)

func SameSite(r *http.Request) bool {
~>	return strings.Contains(r.Header.Get("Referer"), "acme.com")
}
