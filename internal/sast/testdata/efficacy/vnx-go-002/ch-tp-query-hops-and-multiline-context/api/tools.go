package api

import (
	"fmt"
	"net/http"
	"os/exec"

	"github.com/gin-gonic/gin"
)

func Ping(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	host := q.Get("host")
	cmdline := fmt.Sprintf("ping -c 3 %s", host)
~>	out, err := exec.Command("/bin/sh", "-c", cmdline).Output()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.Write(out)
}

func Thumbnail(c *gin.Context) {
~>	cmd := exec.CommandContext(
		c.Request.Context(),
		"sh",
		"-c",
		"convert "+c.Query("file")+" -resize 128x128 thumb.png",
	)
	if err := cmd.Run(); err != nil {
		c.AbortWithStatus(http.StatusInternalServerError)
	}
}
