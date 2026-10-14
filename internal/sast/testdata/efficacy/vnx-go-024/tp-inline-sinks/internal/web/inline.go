package web

import (
	"fmt"
	"net/http"
	"os"
)

func Next(w http.ResponseWriter, r *http.Request) {
~>	http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
}

func Fetch(w http.ResponseWriter, r *http.Request) {
~>	resp, err := http.Get(r.FormValue("url"))
	if err == nil {
		resp.Body.Close()
	}
~>	req, _ := http.NewRequest(http.MethodGet, r.Header.Get("X-Upstream"), nil)
	_ = req
}

func Read(w http.ResponseWriter, r *http.Request) {
~>	b, err := os.ReadFile(r.URL.Query().Get("f"))
	if err == nil {
		w.Write(b)
	}
~>	fmt.Fprintf(w, "<p>%s</p>", r.Header.Get("X-Name"))
}
