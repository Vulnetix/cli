package web

import "github.com/gin-gonic/gin"

func Logout(c *gin.Context) {
	c.SetCookie("sid", "", -1, "/", "shop.example", true, true)
	c.Redirect(302, "/")
}
