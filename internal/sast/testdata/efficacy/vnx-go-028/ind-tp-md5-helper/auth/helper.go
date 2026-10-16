package auth

import "net/http"

func Register(w http.ResponseWriter, r *http.Request) {
~>	pass := Md5Sum(r.FormValue("password"))
	save(r.FormValue("user"), pass)
}
