package web

import "github.com/gin-gonic/gin"

func Login(c *gin.Context, token string) {
~>	c.SetCookie("session", token, 3600, "/", "", false, true)
}
