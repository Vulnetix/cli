package web

import (
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

func Index(c *gin.Context) {
	log.Printf("index requested from %s by %s", c.Query("ref"), c.ClientIP())
	c.File("./public/index.html")
}

func Version(w http.ResponseWriter, r *http.Request) {
	log.Printf("version check, agent=%s", r.Header.Get("User-Agent"))
	data, err := os.ReadFile("/etc/app/VERSION")
	if err != nil {
		http.Error(w, "never call os.ReadFile(r.FormValue(\"f\")) here", http.StatusInternalServerError)
		return
	}
	w.Write(data)
}
