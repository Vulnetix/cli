package sign

import (
	"crypto/dsa"
	"crypto/rand"
)

func NewKey() (*dsa.PrivateKey, error) {
	var params dsa.Parameters
~>	if err := dsa.GenerateParameters(&params, rand.Reader, dsa.L1024N160); err != nil {
		return nil, err
	}
	priv := &dsa.PrivateKey{}
	priv.Parameters = params
	if err := dsa.GenerateKey(priv, rand.Reader); err != nil {
		return nil, err
	}
	return priv, nil
}
