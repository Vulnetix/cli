package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

var v = validator.New()

type Item struct {
	Name string `validate:"required"`
}

func CreateItem(c *gin.Context) {
	var in Item
	err := c.ShouldBindJSON(&in)
	if err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	if verr := v.Struct(in); verr != nil {
		c.AbortWithStatus(http.StatusUnprocessableEntity)
		return
	}
	if c.BindQuery(&in) != nil {
		return
	}
	c.Status(http.StatusCreated)
}
