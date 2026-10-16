package auth

import "math/rand/v2"

func TempPassword() string {
	const cs = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	out := make([]byte, 12)
	for i := range out {
~>		out[i] = cs[rand.IntN(len(cs))]
	}
	return string(out)
}
