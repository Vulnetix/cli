package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type AuthController struct {
	svc AuthService
}

~>func (a *AuthController) PostLogin(ctx *gin.Context) {
	user, pass := ctx.PostForm("username"), ctx.PostForm("password")
	tok, err := a.svc.Login(ctx, user, pass)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"token": tok})
}
