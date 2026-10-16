package web

import "github.com/gin-gonic/gin"

func login(c *gin.Context, token string) {
~>	c.SetCookie("access_token", token, 3600, "/", "example.com", true, false)
	c.JSON(200, gin.H{"ok": true})
}
