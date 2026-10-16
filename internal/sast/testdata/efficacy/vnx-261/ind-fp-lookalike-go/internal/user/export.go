package user

import "encoding/hex"

type Record struct {
	PasswordHash []byte
	ResetToken   []byte
}

func Export(r Record) map[string]string {
	return map[string]string{
		"hash":  hex.EncodeToString(r.PasswordHash),
		"reset": hex.EncodeToString(r.ResetToken),
	}
}
