package loadgen

import "math/rand"

var shuffler = rand.New(rand.NewSource(1))

func Order(targets []string) []string {
	shuffler.Shuffle(len(targets), func(i, j int) { targets[i], targets[j] = targets[j], targets[i] })
	return targets
}
