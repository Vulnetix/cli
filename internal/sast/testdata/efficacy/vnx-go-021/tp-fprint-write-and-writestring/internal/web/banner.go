package web

import (
	"fmt"
	"io"
	"net/http"
)

func Banner(w http.ResponseWriter, r *http.Request) {
	msg := r.FormValue("msg")
~>	fmt.Fprint(w, "<div class=\"banner\">"+msg+"</div>")
	user := r.Header.Get("X-User")
~>	io.WriteString(w, "<b>"+user+"</b>")
	q := r.URL.Query().Get("q")
~>	w.Write([]byte("<h2>Results for " + q + "</h2>"))
~>	fmt.Fprintln(w, "<p>"+r.FormValue("note")+"</p>")
}
