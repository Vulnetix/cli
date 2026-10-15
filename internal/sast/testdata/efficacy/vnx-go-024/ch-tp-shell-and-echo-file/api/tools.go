package api

import (
	"context"
	"net/http"
	"os"
	"os/exec"

	"github.com/labstack/echo/v4"
)

func Ping(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	script := "ping -c 1 " + host
~>	out, _ := exec.CommandContext(context.Background(), "sh", "-c", script).Output()
	w.Write(out)
}

func Download(c echo.Context) error {
	f := c.QueryParam("file")
~>	data, err := os.ReadFile("./files/" + f)
	if err != nil {
		return err
	}
	return c.Blob(http.StatusOK, "application/octet-stream", data)
}
