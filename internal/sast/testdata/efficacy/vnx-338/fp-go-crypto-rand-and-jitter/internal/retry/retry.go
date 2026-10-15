package retry

import (
	crand "crypto/rand"
	"encoding/hex"
	mrand "math/rand"
	"time"
)

func NewToken() string {
	b := make([]byte, 32)
	_, _ = crand.Read(b)
	return hex.EncodeToString(b)
}

func Backoff(attempt int) time.Duration {
	return time.Duration(attempt*100+mrand.Intn(50)) * time.Millisecond
}

func Shard(n int) int {
	return mrand.Intn(n)
}
