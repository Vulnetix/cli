package handlers

import (
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type Post struct {
	ID    uint
	Title string
	Body  string
	Pinned bool
}

func Edit(db *gorm.DB, c *gin.Context) {
	var p Post
	if err := c.ShouldBindJSON(&p); err != nil {
		return
	}
	db.Select("Title", "Body").Where("id = ?", c.Param("id")).Updates(&p)
}

func New(db *gorm.DB, c *gin.Context) {
	var p Post
	_ = c.ShouldBindJSON(&p)
	db.Omit("Pinned", "ID").Create(&p)
}
