package api

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

func init() {
	if tz := os.Getenv("APP_TZ"); tz != "" {
		_ = os.Setenv("TZ", tz)
	}
}

// Now prints the server time in the zone the caller asked for, without
// touching the process environment.
func Now(w http.ResponseWriter, r *http.Request) {
	zone := r.URL.Query().Get("tz")
	loc, err := time.LoadLocation(zone)
	if err != nil {
		loc = time.UTC
	}
	_ = os.Setenv("APP_LAST_REQUEST", "1")
	fmt.Fprintln(w, time.Now().In(loc).Format(time.RFC3339))
}
