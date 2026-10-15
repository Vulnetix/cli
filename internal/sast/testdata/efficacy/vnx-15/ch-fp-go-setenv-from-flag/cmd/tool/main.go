package main

import (
	"flag"
	"net/http"
	"os"
)

func main() {
	tz := flag.String("tz", "UTC", "time zone")
	flag.Parse()
	os.Setenv("TZ", *tz)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.URL.Query().Get("q")))
	})
	http.ListenAndServe(":8080", nil)
}
