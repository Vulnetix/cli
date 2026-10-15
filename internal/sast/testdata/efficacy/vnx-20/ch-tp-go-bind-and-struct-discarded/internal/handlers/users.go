package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

var validate = validator.New()

type CreateUser struct {
	Email string `json:"email" binding:"required,email"`
	Age   int    `json:"age" validate:"gte=18"`
}

func Create(c *gin.Context) {
	var in CreateUser
~>	c.ShouldBindJSON(&in)
~>	validate.Struct(in)
	save(in)
	c.Status(http.StatusCreated)
}

func Update(c *gin.Context) {
	var in CreateUser
~>	_ = c.ShouldBindQuery(&in)
	save(in)
	c.Status(http.StatusOK)
}
