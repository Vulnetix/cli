package preview

import (
	"io"
	"net/http"
	"strings"
)

// Adding a scheme is normalisation, not validation: 169.254.169.254 still
// becomes http://169.254.169.254.
func LinkPreview(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}
~>	resp, err := http.Get(target)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	io.Copy(w, io.LimitReader(resp.Body, 1<<16))
}
