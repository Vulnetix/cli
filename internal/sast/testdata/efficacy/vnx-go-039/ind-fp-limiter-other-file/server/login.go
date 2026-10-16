package server

import "net/http"

func SignIn(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
}
