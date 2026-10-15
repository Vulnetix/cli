package hooks

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
)

type registration struct {
	CallbackURL string `json:"callback_url"`
	Secret      string `json:"secret"`
}

func Register(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read", http.StatusBadRequest)
		return
	}
	var reg registration
	if err := json.Unmarshal(body, &reg); err != nil {
		http.Error(w, "json", http.StatusBadRequest)
		return
	}
	// confirm the endpoint answers before storing it
~>	resp, err := http.Post(reg.CallbackURL, "application/json", bytes.NewReader([]byte(`{"ping":true}`)))
	if err != nil {
		http.Error(w, "callback unreachable", http.StatusBadGateway)
		return
	}
	resp.Body.Close()
}
