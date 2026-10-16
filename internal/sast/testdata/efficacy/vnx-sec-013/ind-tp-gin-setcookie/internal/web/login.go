package web

import "github.com/gin-gonic/gin"

func Login(c *gin.Context) {
	sid := newSessionID()
~>	c.SetCookie("sid", sid, 3600, "/", "shop.example", false, true)
	c.JSON(200, gin.H{"ok": true})
}
