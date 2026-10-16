package web

import "net/http"

func Hook(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("callback")
~>	req, _ := http.NewRequest("POST", target, nil)
	http.DefaultClient.Do(req)
}
