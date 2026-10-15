package api

import (
	"encoding/json"
	"net/http"
	"os"
)

func DebugEnv(w http.ResponseWriter, r *http.Request) {
	env := os.Environ()
	w.Header().Set("Content-Type", "application/json")
~>	json.NewEncoder(w).Encode(env)
}
