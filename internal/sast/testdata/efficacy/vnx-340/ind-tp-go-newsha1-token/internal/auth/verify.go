package auth

import "github.com/google/uuid"

var ns = uuid.MustParse("1b671a64-40d5-491e-99b0-da01ff1f3341")

func VerificationToken(email string) string {
~>	token := uuid.NewSHA1(ns, []byte(email)).String()
	return token
}
