package web

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

func login(w http.ResponseWriter, r *http.Request) {
~>	sid := fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())
	http.SetCookie(w, &http.Cookie{Name: "session_id", Value: sid, HttpOnly: true})
}
