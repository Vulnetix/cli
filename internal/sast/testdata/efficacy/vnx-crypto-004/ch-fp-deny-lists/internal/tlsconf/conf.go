package tlsconf

import (
	"crypto/aes"
	"crypto/tls"
)

var banned = []uint16{
	@@sample:t[l]s[.][T]LS[_]RS[A][_]W[I]TH[_]RC[4][_]1[2]8[_][S]HA@@,
	@@sample:t[l]s[.][T]LS[_]RS[A][_]W[I]TH[_]3D[E]S[_][E]DE[_]CB[C][_]S[H]A@@,
}

func Block(k []byte) { aes.NewCipher(k) }
