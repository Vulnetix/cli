package token

import "github.com/lestrrat-go/jwx/v2/jwt"

// jwx with verification turned off is reported by VNX-JWT-001.
func Audience(raw []byte) ([]string, error) {
	t, err := jwt.Parse(raw, jwt.WithVerify(false))
	if err != nil {
		return nil, err
	}
	return t.Audience(), nil
}
