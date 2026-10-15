package tokens

import "math/rand"

var prevToken int64 = 5000

func Next() int64 {
~>	token := prevToken + int64(rand.Intn(100))
	prevToken = token
	return token
}
