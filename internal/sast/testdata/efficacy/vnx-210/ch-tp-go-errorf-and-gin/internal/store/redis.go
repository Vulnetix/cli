package store

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

type Config struct {
	Addr          string
	RedisPassword string
}

func Dial(cfg Config) (*redis.Client, error) {
	c := redis.NewClient(&redis.Options{Addr: cfg.Addr, Password: cfg.RedisPassword})
	if c == nil {
~>		return nil, fmt.Errorf(
			"redis dial %s with password %q failed", cfg.Addr, cfg.RedisPassword)
	}
	return c, nil
}

func Check(c *gin.Context) {
	token := c.GetHeader("X-Token")
	if token != "expected" {
~>		c.JSON(http.StatusUnauthorized, gin.H{"error": "bad token " + token})
		return
	}
}
