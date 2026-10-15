package api

import (
	"fmt"
	"net/http"
	"os"
)

func Stats(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("user")
	n := len(user)
	fmt.Fprintf(w, "length=%d", n)
	verbose := r.URL.Query().Get("verbose") == "1"
	if verbose {
		os.Stat("/var/lib/app/state")
	}
}
