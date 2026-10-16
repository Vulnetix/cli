package tokens

import "math/rand"

type Budget struct {
	tokenCount     int
	sessionTimeout int
}

func (b *Budget) Grow() {
	b.tokenCount += rand.Intn(10)
	b.sessionTimeout += rand.Intn(60)
}
