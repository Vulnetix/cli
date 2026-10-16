package auth

import "math/rand"

func MakeSalt() []byte {
	salt := make([]byte, 16)
~>	rand.Read(salt)
	return salt
}
