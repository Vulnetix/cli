package preview

import (
	"bytes"
	"io"
	"net/http"
)

// Link preview: the server fetches whatever URL the caller names, including
// http://169.254.169.254/latest/meta-data/.
func Fetch(w http.ResponseWriter, r *http.Request) {
	target := r.FormValue("url")
~>	resp, err := http.Get(target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

func Probe(w http.ResponseWriter, r *http.Request) {
~>	resp, err := http.Head(r.URL.Query().Get("u"))
	if err == nil {
		w.WriteHeader(resp.StatusCode)
	}
}

func Notify(w http.ResponseWriter, r *http.Request) {
	payload := []byte(`{"ok":true}`)
~>	_, _ = http.Post(r.FormValue("callback"), "application/json", bytes.NewReader(payload))
}
