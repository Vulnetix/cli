package api

import (
	"fmt"
	"os"

	"github.com/gin-gonic/gin"
)

func getReport(c *gin.Context) {
~>	data, err := os.ReadFile(
		fmt.Sprintf("%s/reports/%s", reportRoot, c.Param("name")),
	)
	if err != nil {
		c.Status(404)
		return
	}
	c.Data(200, "application/pdf", data)
}

func saveNote(c *gin.Context) {
	title := c.PostForm("title")
	body := c.PostForm("body")
	notePath := fmt.Sprintf("notes/%s.txt", title)
~>	os.WriteFile(notePath, []byte(body), 0o600)
}
