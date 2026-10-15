package web

import (
	"net/http"
	"strconv"
	"sync/atomic"
)

var sessionCounter uint64

func start(w http.ResponseWriter) {
~>	id := atomic.AddUint64(&sessionCounter, 1)
	http.SetCookie(w, &http.Cookie{Name: "session", Value: strconv.FormatUint(id, 10)})
}
