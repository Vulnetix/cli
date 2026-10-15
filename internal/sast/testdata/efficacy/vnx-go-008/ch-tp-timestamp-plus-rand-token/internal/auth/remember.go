package auth

import (
	"fmt"
	"math/rand"
	"net/http"
	"time"
)

func Remember(w http.ResponseWriter, userID int64) {
~>	token := fmt.Sprintf("%d%d%d", userID, time.Now().UnixNano(), rand.Int63())
	http.SetCookie(w, &http.Cookie{Name: "remember", Value: token, HttpOnly: true, Expires: time.Now().Add(30 * 24 * time.Hour)})
}
