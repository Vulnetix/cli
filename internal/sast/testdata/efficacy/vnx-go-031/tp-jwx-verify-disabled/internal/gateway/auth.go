package gateway

import (
	"net/http"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

func Tenant(r *http.Request) (string, error) {
	payload := []byte(r.Header.Get("X-Tenant-Token"))
~>	tok, err := jwt.Parse(payload, jwt.WithVerify(false))
	if err != nil {
		return "", err
	}
	return tok.Subject(), nil
}

func Subject(r *http.Request) string {
~>	tok, err := jwt.ParseInsecure(
		[]byte(r.Header.Get("Authorization")),
	)
	if err != nil {
		return ""
	}
	return tok.Subject()
}
