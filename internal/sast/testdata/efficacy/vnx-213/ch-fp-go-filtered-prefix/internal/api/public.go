package api

import (
	"fmt"
	"net/http"
	"os"
	"strings"
)

func PublicConfig(w http.ResponseWriter, r *http.Request) {
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "PUBLIC_") {
			fmt.Fprintln(w, kv)
		}
	}
}
