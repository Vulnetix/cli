package web

import "net/http"

func SetCookie(w http.ResponseWriter, name, value string) {
~>	cookie := http.Cookie{
		Name:  name,
		Value: value,
		Path:  "/",
	}
	http.SetCookie(w, &cookie)
}
