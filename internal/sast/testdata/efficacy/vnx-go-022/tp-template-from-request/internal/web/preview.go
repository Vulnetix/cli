package web

import (
	"html/template"
	"net/http"
)

type Account struct {
	Email  string
	APIKey string
}

// A template the requester writes can read every field of the data it is
// executed with, and call its methods (server-side template injection).
func Preview(w http.ResponseWriter, r *http.Request, acct *Account) {
	body := r.FormValue("template")
~>	t, err := template.New("preview").Parse(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	t.Execute(w, acct)
}

func Inline(w http.ResponseWriter, r *http.Request, acct *Account) {
~>	t := template.Must(template.New("x").Parse(r.URL.Query().Get("t")))
	t.Execute(w, acct)
}
