package auth

import (
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

func Who(w http.ResponseWriter, r *http.Request) string {
	bearer := r.Header.Get("Authorization")
~>	token, _ := jwt.Parse(bearer, keyFunc)
	claims := token.Claims.(jwt.MapClaims)
	return claims["sub"].(string)
}
