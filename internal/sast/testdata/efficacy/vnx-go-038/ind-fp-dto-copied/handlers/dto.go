package handlers

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type CreateUserInput struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type User struct {
	ID      uint
	Name    string
	Email   string
	IsAdmin bool
}

func Create(db *gorm.DB, c *gin.Context) {
	var in CreateUserInput
	if err := c.ShouldBindJSON(&in); err != nil {
		return
	}
	db.Create(&User{Name: in.Name, Email: in.Email})
}
