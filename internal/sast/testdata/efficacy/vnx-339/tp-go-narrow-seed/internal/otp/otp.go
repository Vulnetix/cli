package otp

import (
	"fmt"
	"math/rand"
	"os"
)

func NewOTP() string {
~>	rand.Seed(int64(os.Getpid() % 1000))
	return fmt.Sprintf("%06d", rand.Intn(1000000))
}

func NewResetCode(id uint32) string {
~>	r := rand.New(rand.NewSource(int64(uint16(id))))
	resetCode := r.Intn(1000000)
	return fmt.Sprint(resetCode)
}
