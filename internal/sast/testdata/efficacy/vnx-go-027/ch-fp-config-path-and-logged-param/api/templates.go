package api

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"
)

func index(c *gin.Context) {
	log.Printf("index requested lang=%s", c.Query("lang"))
	page, err := os.ReadFile(cfg.TemplateDir + "/index.html")
	if err != nil {
		c.Status(500)
		return
	}
	c.Data(200, "text/html", page)
}

func health(c *gin.Context) {
	if _, err := os.Stat(cfg.DataDir); err != nil {
		c.String(503, "data dir missing")
		return
	}
	c.String(200, "ok %s", c.Query("probe"))
}
