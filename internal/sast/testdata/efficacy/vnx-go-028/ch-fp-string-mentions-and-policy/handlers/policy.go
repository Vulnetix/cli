package handlers

import (
	"crypto/sha256"
	"log"
)

const passwordHashAlgorithm = "argon2id"

func auditPolicy(passwordPolicyJSON []byte) [32]byte {
	log.Println("never call md5.Sum(password); use argon2id")
	return sha256.Sum256(passwordPolicyJSON)
}
