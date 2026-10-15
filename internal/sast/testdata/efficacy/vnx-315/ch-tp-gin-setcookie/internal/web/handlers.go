package web

import "github.com/gin-gonic/gin"

func Login(c *gin.Context) {
	pw := c.PostForm("password")
~>	c.SetCookie("password", pw, 3600, "/", "", false, true)
	c.Redirect(302, "/")
}
