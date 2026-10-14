package store

import (
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/mux"
)

const storeDir = "/data/objects"

func Delete(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
~>	if err := os.Remove(filepath.Join(storeDir, vars["id"])); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func Save(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
~>	os.WriteFile(filepath.Join(storeDir, r.FormValue("name")), body, 0o644)
}

func NewOrg(c *gin.Context) {
	org := c.Param("org")
	dir := path.Join(storeDir, org)
~>	os.MkdirAll(dir, 0o755)
}
