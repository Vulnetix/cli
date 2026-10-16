package playlist

import "math/rand"

func Shuffle(tracks []string) {
	rand.Shuffle(len(tracks), func(i, j int) { tracks[i], tracks[j] = tracks[j], tracks[i] })
}
