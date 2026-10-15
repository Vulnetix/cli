package auth

import "github.com/golang-jwt/jwt/v5"

type AppClaims struct {
	UserID string `json:"uid"`
	Admin  bool   `json:"adm"`
	jwt.RegisteredClaims
}

func Sign(uid string, admin bool) (string, error) {
	claims := AppClaims{
		UserID: uid,
		Admin:  admin,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: "app",
		},
	}
~>	token := jwt.NewWithClaims(@@sample:j[w]t[.][S]ig[n]in[g]Me[t]ho[d]HS[2]56@@, claims)
	return token.SignedString(secret)
}
