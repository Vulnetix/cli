package main

import "github.com/ethereum/go-ethereum/crypto"

func main() {
~>	key, err := crypto.HexToECDSA("@@sample:[0-9a-f]{64}@@")
	if err != nil {
		panic(err)
	}
	_ = key
}
