package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	UserID string `json:"uid"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

func RequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		bearer := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		claims := &Claims{}
~>		if _, _, err := jwt.NewParser().ParseUnverified(bearer, claims); err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		if claims.Role != "admin" {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		c.Next()
	}
}

func userFromRequest(r *http.Request) string {
	raw := r.Header.Get("Authorization")
	parser := new(jwt.Parser)
~>	token, _, err := parser.ParseUnverified(
		strings.TrimPrefix(raw, "Bearer "),
		jwt.MapClaims{},
	)
	if err != nil {
		return ""
	}
	sub, _ := token.Claims.GetSubject()
	return sub
}
