package issuer

import (
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func Mint(sig jose.Signer, subject string) (string, error) {
	cl := jwt.Claims{
		Subject:  subject,
		Issuer:   "issuer",
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}
~>	return jwt.Signed(sig).Claims(cl).Serialize()
}
