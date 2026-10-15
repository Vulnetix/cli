package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

var validate = validator.New()

type OrderRequest struct {
	SKU      string `json:"sku" binding:"required"`
	Quantity int    `json:"quantity" binding:"required,min=1,max=100"`
}

func CreateOrder(c *gin.Context) {
	var req OrderRequest
~>	c.ShouldBindJSON(&req)
	c.JSON(http.StatusCreated, save(req))
}

func SearchOrders(c *gin.Context) {
	var q SearchQuery
~>	_ = c.ShouldBindQuery(&q)
~>	_ = validate.Struct(q)
	c.JSON(http.StatusOK, search(q))
}
