package handlers

import (
	"encoding/gob"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Job struct {
	Name  string
	Steps []string
}

func Submit(c *gin.Context) {
	var job Job
~>	decoder := gob.NewDecoder(
		c.Request.Body,
	)
	if err := decoder.Decode(&job); err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	c.JSON(http.StatusOK, gin.H{"queued": job.Name})
}
