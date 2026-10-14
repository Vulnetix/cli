package web

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func requireLogin(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// HTTP to HTTPS upgrade: the host is the one the browser connected to.
func upgrade(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusMovedPermanently)
}

func dashboard(c *gin.Context) {
	c.Redirect(http.StatusFound, "/dashboard")
}

func legacy(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	record(id)
	http.Redirect(w, r, "/items", http.StatusMovedPermanently)
}

func record(string) {}
