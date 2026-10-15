package auth

import (
	"fmt"
	"math/rand"
	"os"
	"time"
)

func init() {
~>	rand.Seed(time.Now().UnixNano())
}

~>var pidRand = rand.New(rand.NewSource(int64(os.Getpid())))

func Issue() string {
	token := fmt.Sprintf("%x", rand.Int63())
	return token
}
