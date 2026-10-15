package account

import (
	"fmt"
	"math/rand"
)

func GeneratePIN() string {
~>	return fmt.Sprintf("%06d", rand.Intn(1000000))
}

const classes = "@@sample:A[B]CD[E]FG[H]JK[L]MN[P]QR[S]TU[V]WX[Y]Za[b]cd[e]fg[h]ij[k]mn[o]pq[r]st[u]vw[x]yz[2]34[5]67[8]9@@!@#$%"

func TemporaryPassword(n int) string {
	b := []byte(classes[:n])
~>	rand.Shuffle(len(b), func(i, j int) { b[i], b[j] = b[j], b[i] })
	return string(b)
}
