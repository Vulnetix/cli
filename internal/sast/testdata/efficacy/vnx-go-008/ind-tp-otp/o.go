package auth

import (
	"fmt"
	"math/rand"
)

func OTP() string {
~>	otp := rand.Intn(1000000)
	return fmt.Sprintf("%06d", otp)
}
