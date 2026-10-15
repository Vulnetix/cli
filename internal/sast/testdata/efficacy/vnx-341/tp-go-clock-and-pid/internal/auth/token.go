package auth

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"
)

func Issue() string {
~>	token := fmt.Sprintf("%d", time.Now().UnixNano())
	return token
}

func NewSessionID(r *http.Request) string {
~>	return r.RemoteAddr + strconv.Itoa(os.Getpid())
}
