package session

import (
	"fmt"
	"strconv"
	"sync/atomic"
)

var sessionCounter int64
var lastToken int
var resetCounter atomic.Int64

func newSessionID() string {
~>	id := atomic.AddInt64(&sessionCounter, 1)
	return strconv.FormatInt(id, 10)
}

func newToken() string {
~>	token := fmt.Sprintf("%d", lastToken+1)
	return token
}

func resetCode() string {
~>	resetCode := fmt.Sprint(resetCounter.Add(1))
	return resetCode
}
