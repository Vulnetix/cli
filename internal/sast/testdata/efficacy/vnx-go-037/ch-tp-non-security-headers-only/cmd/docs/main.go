package main

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
)

//go:embed site
var site embed.FS

func main() {
	sub, err := fs.Sub(site, "site")
	if err != nil {
		log.Fatal(err)
	}
~>	files := http.FileServer(http.FS(sub))
	http.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		files.ServeHTTP(w, r)
	}))
	log.Fatal(http.ListenAndServe(":8000", nil))
}
