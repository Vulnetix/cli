package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestBindIgnoresUnknownFields(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/cart", strings.NewReader(`{"sku":"a","x":1}`))
	var req addItemRequest
	c.ShouldBindJSON(&req)
	if req.SKU != "a" {
		t.Fatalf("sku = %q", req.SKU)
	}
}
