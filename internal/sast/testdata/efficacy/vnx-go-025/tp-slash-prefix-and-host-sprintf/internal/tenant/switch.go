package tenant

import (
	"fmt"
	"net/http"
)

// "/" + "/evil.example" is the protocol-relative URL //evil.example.
func SwitchLang(w http.ResponseWriter, r *http.Request) {
	lang := r.FormValue("lang")
	dest := "/" + lang
~>	http.Redirect(w, r, dest, http.StatusFound)
}

// A host taken from the request decides where the browser goes.
func Portal(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("tenant")
	u := fmt.Sprintf("https://%s/home", host)
~>	http.Redirect(w, r, u, http.StatusFound)
}

// No slash after the fixed host: "https://app.example.com" + "@evil.example".
func Back(w http.ResponseWriter, r *http.Request) {
	path := r.FormValue("path")
~>	http.Redirect(w, r, "https://app.example.com"+path, http.StatusFound)
}
