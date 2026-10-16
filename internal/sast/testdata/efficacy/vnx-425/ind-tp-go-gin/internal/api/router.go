package api

import "github.com/gin-gonic/gin"

func Routes(r *gin.Engine) {
~>	r.POST("/sysadmin/cache/purge", purgeCache)
	r.GET("/products", listProducts)
}

func purgeCache(c *gin.Context) {
	cache.Purge()
	c.JSON(200, gin.H{"ok": true})
}

func listProducts(c *gin.Context) {
	c.JSON(200, catalog.All())
}
