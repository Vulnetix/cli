package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"example.com/app/internal/models"
)

func CreateUser(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var u models.User
~>		if err := c.ShouldBindJSON(&u); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		db.Create(&u)
		c.JSON(http.StatusCreated, u)
	}
}

func PatchUser(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var input map[string]interface{}
~>		_ = c.Bind(&input)
		db.Model(&models.User{}).Where("id = ?", c.Param("id")).Updates(input)
	}
}
