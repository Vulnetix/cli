package auth

import "github.com/golang-jwt/jwt/v5"

type Claims struct {
	UserID   string `json:"uid"`
~>	Password string `json:"password"`
	jwt.RegisteredClaims
}

func Issue(user User, key []byte) (string, error) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
~>		"api_key": user.APIKey,
		"exp": expiry(),
	})
	return t.SignedString(key)
}
