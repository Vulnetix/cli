package api

import (
	"net/http"
	"strconv"
	"time"
)

type limiter struct{ wait time.Duration }

func (l *limiter) Throttle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", strconv.Itoa(int(l.wait.Seconds())))
	w.Header().Add("Vary", "Accept-Encoding")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Served-At", time.Now().UTC().Format(http.TimeFormat))
	q := r.URL.Query().Get("q")
	w.Write([]byte(strconv.Quote(q)))
}
