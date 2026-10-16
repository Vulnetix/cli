package web

import (
	"encoding/json"
	"net/http"
)

type in struct{ URL string `json:"url"` }

func Preview(w http.ResponseWriter, r *http.Request) {
	var body in
	json.NewDecoder(r.Body).Decode(&body)
~>	resp, _ := http.Get(body.URL)
	_ = resp
}
