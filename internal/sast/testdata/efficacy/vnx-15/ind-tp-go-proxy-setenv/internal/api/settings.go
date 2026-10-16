package api

import (
	"encoding/json"
	"net/http"
	"os"
)

type settingsResponse struct {
	OK bool `json:"ok"`
}

// UpdateProxy lets the admin console change the outbound proxy.
func UpdateProxy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
~>	if err := os.Setenv("HTTPS_PROXY", r.URL.Query().Get("proxy")); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(settingsResponse{OK: true})
}
