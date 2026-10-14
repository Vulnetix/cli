package web

import (
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
)

type Config struct{ LoginURL string }

// The host and path are fixed; the parameter only fills the query string.
func Item(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/items?id="+r.FormValue("id"), http.StatusFound)
}

func SSO(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	http.Redirect(w, r, "https://accounts.example.com/login?next="+url.QueryEscape(next), http.StatusFound)
}

func Canonical(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
}

func Login(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/login", http.StatusFound)
}

func ToLogin(cfg Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Redirect(http.StatusFound, cfg.LoginURL)
	}
}

// http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound) used to be here.
const note = `http.Redirect(w, r, r.URL.Query().Get("next"), 302)`
