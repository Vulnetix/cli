package ops

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

func PublicEnv(w http.ResponseWriter, r *http.Request) {
	public := map[string]string{}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "PUBLIC_") {
			k, v, _ := strings.Cut(kv, "=")
			public[k] = v
		}
	}
	json.NewEncoder(w).Encode(public)
}

func runMigrations() error {
	cmd := exec.Command("./migrate", "up")
	cmd.Env = os.Environ()
	return cmd.Run()
}
