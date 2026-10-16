package main

import "github.com/ethereum/go-ethereum/crypto"

func key() {
~>	k, _ := crypto.HexToECDSA("@@sample:[a-f0-9]{64}@@")
	_ = k
}
