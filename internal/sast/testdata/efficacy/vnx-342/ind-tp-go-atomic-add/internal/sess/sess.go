package sess

import (
	"net/http"
	"strconv"
	"sync/atomic"
)

var lastSessionID int64

func Start(w http.ResponseWriter) {
~>	sessionID := atomic.AddInt64(&lastSessionID, 1)
	http.SetCookie(w, &http.Cookie{Name: "session", Value: strconv.FormatInt(sessionID, 10), HttpOnly: true})
}
