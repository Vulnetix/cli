package web

import (
	"fmt"
	"io"
	"net/http"
)

func Banner(w http.ResponseWriter, r *http.Request) {
	msg := r.FormValue("msg")
~>	fmt.Fprint(w, "<div class=\"banner\">"+msg+"</div>")
}

func Results(w http.ResponseWriter, r *http.Request) {
	q := r.FormValue("q")
~>	w.Write([]byte("<h2>Results for " + q + "</h2>"))
}

func Title(w http.ResponseWriter, r *http.Request) {
	t := r.FormValue("t")
~>	io.WriteString(w, "<title>"+t+"</title>")
}
