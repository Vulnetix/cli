package session

import (
	"fmt"
	"math/rand/v2"
	mrand "math/rand"
)

~>var rng = mrand.New(mrand.NewSource(42))

func NewSessionID() string { return fmt.Sprintf("%016x", rng.Uint64()) }

func signingStream() *rand.ChaCha8 {
~>	return rand.NewChaCha8([32]byte([]byte("@@sample:0[1]23[4]56[7]89[a]bc[d]ef[0]12[3]45[6]78[9]ab[c]de[f]@@")))
}
