package main

import (
	"log"
	"net/http"
	"os"
	"plugin"
)

func main() {
	if path := os.Getenv("AUTH_PLUGIN"); path != "" {
		p, err := plugin.Open(path)
		if err != nil {
			log.Fatal(err)
		}
		if _, err := p.Lookup("Init"); err != nil {
			log.Fatal(err)
		}
	}
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		_ = r.URL.Query().Get("verbose")
		w.WriteHeader(http.StatusOK)
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}
