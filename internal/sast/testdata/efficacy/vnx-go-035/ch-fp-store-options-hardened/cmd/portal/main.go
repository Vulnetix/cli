package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gorilla/sessions"
)

var store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY")))

func init() {
	store.Options.HttpOnly = true
	store.Options.Secure = true
	store.Options.SameSite = http.SameSiteLaxMode
}

func main() {
	log.Fatal(http.ListenAndServe(":8080", nil))
}
