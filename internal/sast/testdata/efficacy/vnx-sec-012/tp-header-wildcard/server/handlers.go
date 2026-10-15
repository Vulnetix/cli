package server

import "net/http"

func profile(w http.ResponseWriter, r *http.Request) {
~>	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}
