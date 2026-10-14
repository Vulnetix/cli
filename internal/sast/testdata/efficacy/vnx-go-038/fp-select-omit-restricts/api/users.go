package api

import "github.com/gin-gonic/gin"

func Patch(c *gin.Context) {
	var in User
	if err := c.ShouldBindJSON(&in); err != nil {
		return
	}
	db.Model(&User{ID: id(c)}).Select("Name", "Email").Updates(in)
	db.Omit("Role", "IsAdmin").Save(&in)
}
