package telemetry

import "math/rand"

type Sampler struct {
	every int
	next  int
	rng   *rand.Rand
}

func NewSampler(every int, seed int64) *Sampler {
	s := &Sampler{every: every, rng: rand.New(rand.NewSource(seed))}
	s.Reset()
	return s
}

// Reset picks the offset of the next sampled event.
func (s *Sampler) Reset() {
	s.next = s.rng.Intn(s.every)
}

func ResetCounters(buckets []int) {
	for i := range buckets {
		buckets[i] = rand.Intn(3)
	}
}
