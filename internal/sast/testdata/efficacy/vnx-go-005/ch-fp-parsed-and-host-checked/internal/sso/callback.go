package sso

import (
	"net/http"
	"net/url"
)

func Callback(w http.ResponseWriter, r *http.Request) {
	returnTo := r.FormValue("return_to")
	u, err := url.Parse(returnTo)
	if err != nil || u.IsAbs() || u.Host != "" {
		returnTo = "/"
	}
	http.Redirect(w, r, returnTo, http.StatusFound)
}
