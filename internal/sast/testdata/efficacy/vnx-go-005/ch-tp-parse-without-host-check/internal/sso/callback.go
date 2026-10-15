package sso

import (
	"net/http"
	"net/url"
)

// Parsing only proves the string is a URL; https://evil.example parses fine.
func Callback(w http.ResponseWriter, r *http.Request) {
	returnTo := r.FormValue("return_to")
	if _, err := url.Parse(returnTo); err != nil {
		http.Error(w, "bad return_to", http.StatusBadRequest)
		return
	}
~>	http.Redirect(w, r, returnTo, http.StatusFound)
}
