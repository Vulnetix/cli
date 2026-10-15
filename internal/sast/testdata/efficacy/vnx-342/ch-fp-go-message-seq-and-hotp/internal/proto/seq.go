package proto

import "sync/atomic"

var seq uint64

func nextSeq() uint64 {
	msgSeq := atomic.AddUint64(&seq, 1)
	return msgSeq
}

func code(secret []byte, counter uint64) string {
	return hotp(secret, counter+1)
}
