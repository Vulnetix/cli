package ops

import (
	"encoding/json"
	"net/http"
	"os"
)

func EnvHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
~>	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "env": os.Environ()})
}
