package tokens

import (
	"math/rand"
	"strconv"
)

var lastToken int64 = 5_000_000

func Next() string {
~>	token := lastToken + int64(rand.Intn(500))
	lastToken = token
	return strconv.FormatInt(token, 10)
}
