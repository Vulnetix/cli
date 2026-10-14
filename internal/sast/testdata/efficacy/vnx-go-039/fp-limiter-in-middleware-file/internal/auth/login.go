package auth

import "net/http"

func HandleLogin(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}
