package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"example.com/app/internal/models"
)

type signupRequest struct {
	Name     string `json:"name" binding:"required"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=12"`
}

func (h *Handler) Signup(c *gin.Context) {
	var req signupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.AbortWithStatus(http.StatusBadRequest)
		return
	}
	hash, err := hashPassword(req.Password)
	if err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
		return
	}
	user := models.User{
		Name:         req.Name,
		Email:        req.Email,
		PasswordHash: hash,
		Role:         models.RoleMember,
	}
	if err := h.db.Create(&user).Error; err != nil {
		c.AbortWithStatus(http.StatusConflict)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": user.ID})
}
