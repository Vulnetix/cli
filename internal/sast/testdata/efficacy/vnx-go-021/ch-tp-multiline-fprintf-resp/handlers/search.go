package handlers

import (
	"fmt"
	"net/http"
)

func Search(resp http.ResponseWriter, req *http.Request) {
	q := req.URL.Query().Get("q")
~>	fmt.Fprintf(resp,
		"<html><body>Results for <b>%v</b></body></html>",
		q)
}

func Echo(w http.ResponseWriter, r *http.Request) {
	msg := r.FormValue("msg")
~>	w.Write([]byte("<p class=\"echo\">" + msg + "</p>"))
}
