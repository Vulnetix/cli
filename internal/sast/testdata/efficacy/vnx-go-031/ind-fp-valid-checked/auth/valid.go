package auth

import "github.com/golang-jwt/jwt/v5"

func Subject(raw string) (string, bool) {
	token, err := jwt.Parse(raw, keyFunc)
	if err != nil || !token.Valid {
		return "", false
	}
	return token.Claims.(jwt.MapClaims)["sub"].(string), true
}
