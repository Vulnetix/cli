package web

import (
	"fmt"
	"net/http"
)

func Items(rw http.ResponseWriter, req *http.Request) {
	item := req.FormValue("item")
~>	fmt.Fprintf(rw, "<div class='item'>%v</div>", item)
}

func Greet(res http.ResponseWriter, q *http.Request) {
~>	fmt.Fprintf(res, "<span>%s</span>", q.Header.Get("X-User"))
}

type handler struct{}

func (handler) ServeHTTP(out http.ResponseWriter, in *http.Request) {
~>	fmt.Fprintf(out,
		"<a href=\"%s\">continue</a>", in.FormValue("next"))
}
