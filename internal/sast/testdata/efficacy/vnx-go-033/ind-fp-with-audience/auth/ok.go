package auth

import "github.com/golang-jwt/jwt/v5"

func Check(raw string, kf jwt.Keyfunc) (*jwt.Token, error) {
	return jwt.Parse(raw, kf,
		jwt.WithIssuer("https://id.example.com"),
		jwt.WithAudience("orders-api"),
	)
}

func Check2(raw string, claims jwt.Claims, kf jwt.Keyfunc) (*jwt.Token, error) {
	return jwt.ParseWithClaims(raw, claims, kf, jwt.WithAudience("billing"), jwt.WithLeeway(5))
}
