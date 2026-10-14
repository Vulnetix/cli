package main

import (
	_ "expvar"
	"net/http"

	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
)

func main() {
	go func() {
		// expvar publishes /debug/vars (memstats, cmdline) on the default mux.
~>		http.ListenAndServe(":8081", nil)
	}()

	r := gin.Default()
	pprof.Register(r)
	r.GET("/ping", func(c *gin.Context) { c.String(http.StatusOK, "pong") })
~>	r.Run(":8080")
}
