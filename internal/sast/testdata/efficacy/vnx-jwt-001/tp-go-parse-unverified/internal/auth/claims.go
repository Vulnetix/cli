package auth

import (
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

func UserFromRequest(r *http.Request) (string, error) {
	raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims := jwt.MapClaims{}
~>	if _, _, err := jwt.NewParser().ParseUnverified(raw, claims); err != nil {
		return "", err
	}
	return claims["sub"].(string), nil
}

func Role(token string) string {
	claims := jwt.MapClaims{}
~>	new(jwt.Parser).ParseUnverified(token, &claims)
	return claims["role"].(string)
}
