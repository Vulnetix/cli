package sign

import (
	"crypto/dsa"
	"crypto/rand"
)

func Params() (dsa.Parameters, error) {
	var p dsa.Parameters
	err := dsa.GenerateParameters(&p, rand.Reader, dsa.L2048N256)
	return p, err
}
