package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type User struct {
	ID      uint
	Name    string
	Email   string
	IsAdmin bool
}

func CreateUser(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var u User
~>		if err := c.ShouldBindJSON(&u); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if err := db.Create(&u).Error; err != nil {
			c.JSON(500, gin.H{"error": "db"})
			return
		}
		c.JSON(201, u)
	}
}
