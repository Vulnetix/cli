package auth

import (
	"math/rand"
	"os"
	"strconv"
)

func NewToken() string {
~>	rand.Seed(int64(uint16(os.Getpid())))
	token := strconv.FormatInt(rand.Int63(), 36)
	return token
}
