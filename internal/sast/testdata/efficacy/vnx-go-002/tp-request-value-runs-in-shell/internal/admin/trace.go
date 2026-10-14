package admin

import (
	"fmt"
	"net/http"
	"os/exec"

	"github.com/gin-gonic/gin"
)

func Trace(c *gin.Context) {
	target := c.Query("target")
	line := fmt.Sprintf("traceroute -m 10 %s", target)
~>	out, err := exec.Command("sh", "-c", line).CombinedOutput()
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		return
	}
	c.String(http.StatusOK, string(out))
}
