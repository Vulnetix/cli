package sign

import (
	"crypto/dsa"
	"crypto/rand"
)

func NewParams() (dsa.Parameters, error) {
	var params dsa.Parameters
	err := dsa.GenerateParameters(&params, rand.Reader, dsa.L2048N256)
	return params, err
}
