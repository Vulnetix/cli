package server

import "github.com/gin-gonic/gin"

~>func SignIn(c *gin.Context) {
	var body struct{ Email, Password string }
	if err := c.ShouldBindJSON(&body); err != nil {
		c.AbortWithStatus(400)
		return
	}
	c.JSON(200, gin.H{"token": issue(body.Email)})
}
