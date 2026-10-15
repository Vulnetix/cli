package web

import (
	"net/http"
	"net/url"

	"github.com/golang-jwt/jwt/v5"
)

func callback(w http.ResponseWriter, r *http.Request) {
	next, _ := url.Parse(r.URL.Query().Get("next"))
	claims := jwt.MapClaims{}
~>	if _, _, err := jwt.NewParser().ParseUnverified(r.URL.Query().Get("token"), claims); err != nil {
		http.Error(w, "bad token", http.StatusUnauthorized)
		return
	}
	http.Redirect(w, r, next.Path, http.StatusFound)
}
