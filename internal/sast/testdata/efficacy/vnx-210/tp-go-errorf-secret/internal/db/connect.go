package db

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

type Config struct {
	Host     string
	User     string
	Password string
	DSN      string
}

func Open(cfg Config) error {
	if err := ping(cfg.Host); err != nil {
~>		return fmt.Errorf("connect %s as %s/%s: %w", cfg.Host, cfg.User, cfg.Password, err)
	}
	return nil
}

func Check(apiKey string) error {
	if !valid(apiKey) {
~>		return errors.New("api key rejected: " + apiKey)
	}
	return nil
}

func Login(w http.ResponseWriter, user, password string) {
	if !auth(user, password) {
~>		http.Error(w, fmt.Sprintf("bad credentials for %s: %s", user, password), http.StatusUnauthorized)
	}
}

func Refresh(c *gin.Context, refreshToken string) {
	if !verify(refreshToken) {
~>		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token " + refreshToken})
	}
}

func Dial(dsn string) error {
	if _, err := sqlOpen(dsn); err != nil {
~>		return fmt.Errorf(
			"cannot open database %q: %v",
			dsn, err)
	}
	return nil
}
