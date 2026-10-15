package auth

import "github.com/golang-jwt/jwt/v5"

func Parse(raw string, kf jwt.Keyfunc) (*jwt.Token, error) {
~>	return jwt.Parse(raw, kf, jwt.WithValidMethods([]string{"HS256", "none"}))
}
