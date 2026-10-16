package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

type addItemRequest struct {
	SKU      string `json:"sku" binding:"required"`
	Quantity int    `json:"quantity" binding:"required,min=1"`
}

var validate = validator.New()

func AddItem(c *gin.Context) {
	var req addItemRequest
~>	c.ShouldBindJSON(&req)
	cart.Add(req.SKU, req.Quantity)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

type searchQuery struct {
	Term string `validate:"required,max=64"`
}

func Search(c *gin.Context) {
	q := searchQuery{Term: c.Query("q")}
~>	_ = validate.Struct(q)
	c.JSON(http.StatusOK, catalog.Find(q.Term))
}
