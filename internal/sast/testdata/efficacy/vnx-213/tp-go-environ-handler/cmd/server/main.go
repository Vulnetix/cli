package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

func envHandler(w http.ResponseWriter, r *http.Request) {
~>	json.NewEncoder(w).Encode(os.Environ())
}

func debugHandler(w http.ResponseWriter, r *http.Request) {
~>	for _, kv := range os.Environ() {
		fmt.Fprintln(w, kv)
	}
}

func main() {
	http.HandleFunc("/env", envHandler)
	http.HandleFunc("/debug", debugHandler)
	http.ListenAndServe(":8080", nil)
}
