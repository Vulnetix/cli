package main

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	rscors "github.com/rs/cors"
)

func main() {
	r := gin.Default()
	r.Use(cors.New(cors.Config{
~>		AllowAllOrigins:  true,
		AllowCredentials: true,
	}))
	c := rscors.New(rscors.Options{
~>		AllowOriginFunc:  func(origin string) bool { return true },
		AllowCredentials: true,
	})
	_ = c
}
