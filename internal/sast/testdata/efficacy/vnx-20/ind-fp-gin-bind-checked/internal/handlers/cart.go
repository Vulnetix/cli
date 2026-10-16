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
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	cart.Add(req.SKU, req.Quantity)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func Search(c *gin.Context) {
	q := searchQuery{Term: c.Query("q")}
	err := validate.Struct(q)
	if err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	c.JSON(http.StatusOK, catalog.Find(q.Term))
}
