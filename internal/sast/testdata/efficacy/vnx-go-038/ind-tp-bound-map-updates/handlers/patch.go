package handlers

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func Patch(db *gorm.DB, c *gin.Context) {
	var input map[string]interface{}
~>	_ = c.ShouldBindJSON(&input)
	db.Model(&Account{}).Where("id = ?", c.Param("id")).Updates(input)
}

type Account struct{ ID uint }
