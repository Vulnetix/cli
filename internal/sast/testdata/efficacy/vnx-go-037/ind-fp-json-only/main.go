package main

import (
	"encoding/json"
	"net/http"
)

func status(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func main() {
	http.HandleFunc("/status", status)
	http.ListenAndServe(":8080", nil)
}
