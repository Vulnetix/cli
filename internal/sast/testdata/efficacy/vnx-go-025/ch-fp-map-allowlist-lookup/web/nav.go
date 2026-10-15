package web

import "net/http"

var destinations = map[string]string{
	"home":     "/",
	"settings": "/account/settings",
	"billing":  "/account/billing",
}

func Go(w http.ResponseWriter, r *http.Request) {
	dest, ok := destinations[r.URL.Query().Get("to")]
	if !ok {
		dest = "/"
	}
	http.Redirect(w, r, dest, http.StatusFound)
}
