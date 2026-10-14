package auth

import (
	"net/http"
	"net/url"
)

var allowedReturn = map[string]bool{"/": true, "/account": true}

func Done(w http.ResponseWriter, r *http.Request) {
	ret := r.FormValue("return")
	if !allowedReturn[ret] {
		ret = "/"
	}
	http.Redirect(w, r, ret, http.StatusFound)
}

func Callback(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	u, err := url.Parse(target)
	if err != nil || u.IsAbs() || u.Host != "" {
		http.Error(w, "bad redirect", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func Resume(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	if !isSafeRedirect(next) {
		next = "/"
	}
	http.Redirect(w, r, next, http.StatusFound)
}

func Inline(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, safeRedirect(r.FormValue("next")), http.StatusFound)
}

func isSafeRedirect(s string) bool { return len(s) > 0 && s[0] == '/' && (len(s) == 1 || s[1] != '/') }

func safeRedirect(s string) string {
	if isSafeRedirect(s) {
		return s
	}
	return "/"
}
