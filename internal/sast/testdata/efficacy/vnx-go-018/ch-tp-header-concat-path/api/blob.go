package api

import (
	"io"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

var dataDir = "/srv/blobs"

func PutBlob(w http.ResponseWriter, r *http.Request) {
	name := r.Header.Get("X-Blob-Name")
	dest := dataDir + "/" + name
	body, _ := io.ReadAll(r.Body)
~>	if err := ioutil.WriteFile(dest, body, 0o644); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func NewTenant(w http.ResponseWriter, r *http.Request) {
~>	if err := os.MkdirAll(dataDir+"/"+mux.Vars(r)["tenant"], 0o755); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}
