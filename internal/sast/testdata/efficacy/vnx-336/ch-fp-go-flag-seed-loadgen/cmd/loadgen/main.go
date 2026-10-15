package main

import (
	"flag"
	"math/rand"
)

const MaxTokens = 42

func main() {
	seed := flag.Int64("seed", 1, "seed for reproducible load")
	flag.Parse()
	r := rand.New(rand.NewSource(*seed))
	burst := r.Intn(MaxTokens)
	run(burst)
}
