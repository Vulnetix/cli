package session

import "math/rand"

var lastSessionID uint64 = 4242

func NextSessionID() uint64 {
~>	nextSessionID := lastSessionID + uint64(rand.Intn(1000))
	lastSessionID = nextSessionID
	return nextSessionID
}
