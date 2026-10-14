package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
)

// Download reads os.ReadFile("/uploads/" + r.FormValue("file")) in the bad version.
func main() {
	cfg := flag.String("config", "app.yaml", "config file")
	flag.Parse()
	data, err := os.ReadFile(*cfg)
	if err != nil {
		fmt.Println("os.Open(r.FormValue(\"x\")) is unsafe")
		os.Exit(1)
	}
	_ = data
	in, _ := os.Open(filepath.Join(os.Getenv("HOME"), ".tool", os.Args[1]))
	defer in.Close()
}

func Static(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./public/index.html")
	_ = r.FormValue("ignored")
}

// http.ServeFile rejects ".." elements in r.URL.Path itself.
func Pages(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, filepath.Join("./site", r.URL.Path))
}
