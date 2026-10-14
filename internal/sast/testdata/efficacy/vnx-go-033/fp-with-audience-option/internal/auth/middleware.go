package auth

import "github.com/golang-jwt/jwt/v5"

var strict = jwt.NewParser(
	jwt.WithValidMethods([]string{"RS256"}),
	jwt.WithAudience("api.example.com"),
)

func Verify(raw string, kf jwt.Keyfunc) error {
	_, err := jwt.Parse(raw, kf,
		jwt.WithIssuer("https://id.example.com"),
		jwt.WithAudience("api.example.com"),
	)
	return err
}

func VerifyStrict(raw string, kf jwt.Keyfunc) error {
	_, err := strict.Parse(raw, kf)
	return err
}
