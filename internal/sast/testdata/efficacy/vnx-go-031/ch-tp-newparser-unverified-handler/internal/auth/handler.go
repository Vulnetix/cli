package auth

import (
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

func Profile(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims := jwt.MapClaims{}
~>	if _, _, err := jwt.NewParser().ParseUnverified(raw, claims); err != nil {
		http.Error(w, "bad token", http.StatusUnauthorized)
		return
	}
	w.Write([]byte(claims["sub"].(string)))
}
