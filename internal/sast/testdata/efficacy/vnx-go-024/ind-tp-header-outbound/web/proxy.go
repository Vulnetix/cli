package web

import "net/http"

func Proxy(w http.ResponseWriter, r *http.Request) {
~>	req, _ := http.NewRequest(http.MethodGet, r.Header.Get("X-Upstream"), nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "bad gateway", 502)
		return
	}
	defer resp.Body.Close()
}
