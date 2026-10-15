package handlers

import (
	"crypto/md5"
	"encoding/hex"
	"net/http"
)

func Register(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	pw := r.FormValue("password")
~>	sum := md5.Sum([]byte(pw))
	saveUser(username, hex.EncodeToString(sum[:]))
}
