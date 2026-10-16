package authn

import (
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

func UserFromRequest(r *http.Request) (string, error) {
	raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	claims := jwt.MapClaims{}
~>	_, _, err := jwt.NewParser().ParseUnverified(raw, claims)
	if err != nil {
		return "", err
	}
	sub, _ := claims["sub"].(string)
	return sub, nil
}
