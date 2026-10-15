package main

import (
	"log"
	"net/http"
	"os"

	"github.com/gorilla/sessions"
)

~>var store = sessions.NewFilesystemStore(os.TempDir(), []byte(os.Getenv("SESSION_KEY")))

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s, _ := store.Get(r, "portal")
		s.Values["seen"] = true
		_ = s.Save(r, w)
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}
