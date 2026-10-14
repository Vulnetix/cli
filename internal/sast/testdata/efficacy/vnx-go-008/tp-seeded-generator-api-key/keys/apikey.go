package keys

import (
	"fmt"
	"math/rand"
	"time"
)

var rng = rand.New(rand.NewSource(time.Now().UnixNano()))

func CreateAPIKey(owner string) Key {
~>	secret := fmt.Sprintf("%x%x", rng.Int63(),
		rng.Int63())
	return Key{Owner: owner, Secret: secret}
}
