package auth

import (
	"crypto/sha1"
	"encoding/hex"
	"net/http"
)

func Login(w http.ResponseWriter, r *http.Request) {
	pw := r.FormValue("password")
~>	d := sha1.Sum([]byte(pw))
	if lookup(r.FormValue("user")) == hex.EncodeToString(d[:]) {
		w.WriteHeader(200)
	}
}
