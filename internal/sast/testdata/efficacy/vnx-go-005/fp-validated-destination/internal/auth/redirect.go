package auth

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

var allowedHosts = map[string]bool{"app.example.com": true}

func LoginDone(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		next = "/"
	}
	http.Redirect(w, r, next, http.StatusFound)
}

func Partner(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("target")
	u, err := url.Parse(target)
	if err != nil || !allowedHosts[u.Host] {
		http.Error(w, "bad redirect", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func GinBack(c *gin.Context) {
	back := c.Query("back")
	if !isLocalURL(back) {
		back = "/"
	}
	c.Redirect(http.StatusFound, back)
}

// The helper is the check.
func Wrapped(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, safeRedirect(r.URL.Query().Get("next")), http.StatusFound)
}

func isLocalURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Host == "" && u.Scheme == "" && strings.HasPrefix(s, "/")
}

func safeRedirect(s string) string {
	if isLocalURL(s) {
		return s
	}
	return "/"
}
