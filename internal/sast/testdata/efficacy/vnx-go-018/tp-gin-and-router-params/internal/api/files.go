package api

import (
	"net/http"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/mux"
)

func GinUpload(c *gin.Context) {
	file, err := c.FormFile("upload")
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}
~>	c.SaveUploadedFile(file, "./uploads/"+file.Filename)
}

func GinWrite(c *gin.Context) {
	dst := filepath.Join("data", c.Param("name"))
~>	os.WriteFile(dst, []byte(c.PostForm("content")), 0o644)
}

func MuxCreate(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
~>	f, err := os.Create("/srv/reports/" + vars["report"])
	if err == nil {
		f.Close()
	}
}

func ChiCreate(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	out := filepath.Join("/srv/pages", slug+".html")
~>	os.WriteFile(out, []byte("<html></html>"), 0o644)
}

func PathValueCreate(w http.ResponseWriter, r *http.Request) {
~>	os.Create(filepath.Join("/srv/blobs", r.PathValue("id")))
}
