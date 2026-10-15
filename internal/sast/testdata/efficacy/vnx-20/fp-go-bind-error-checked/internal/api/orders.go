package api

import (
	"net"
	"net/http"

	"github.com/gin-gonic/gin"
)

func CreateOrder(c *gin.Context) {
	var req OrderRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	err := validate.Struct(req)
	if err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	// c.ShouldBindJSON(&req) without the error check would be a bug
	c.JSON(http.StatusCreated, save(req))
}

func listen(l *net.UDPConn) {
	log.Println("call c.Bind(&x) and check the error")
}
