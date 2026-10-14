package assets

import (
	"crypto/sha256"
	"fmt"
	"mime"
	"net/http"
	"path/filepath"
)

// The headers carry a digest of the parameter and a registered MIME type
// chosen by its extension; neither can hold the parameter's own bytes.
func Serve(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	sum := sha256.Sum256([]byte(name))
	etag := fmt.Sprintf("%x", sum)
	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Type", mime.TypeByExtension(filepath.Ext(name)))
	n := len(name)
	w.Header().Set("X-Name-Length", fmt.Sprintf("%d", n))
}
