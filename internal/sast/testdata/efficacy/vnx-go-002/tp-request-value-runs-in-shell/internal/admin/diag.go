package admin

import (
	"net/http"
	"os/exec"

	"github.com/gofiber/fiber/v2"
)

func RunHandler(w http.ResponseWriter, r *http.Request) {
	cmd := r.FormValue("cmd")
~>	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write(out)
}

func LookupHandler(w http.ResponseWriter, r *http.Request) {
~>	out, _ := exec.Command("bash", "-c", r.URL.Query().Get("q")).Output()
	w.Write(out)
}

// The program itself is chosen by the requester.
func VersionHandler(w http.ResponseWriter, r *http.Request) {
	tool := r.URL.Query().Get("tool")
~>	out, _ := exec.Command(tool, "--version").Output()
	w.Write(out)
}

func Ping(app *fiber.App) {
	app.Post("/ping", func(c *fiber.Ctx) error {
		host := c.FormValue("host")
~>		out, err := exec.Command("sh", "-c", "ping -c 2 "+host).Output()
		if err != nil {
			return err
		}
		return c.Send(out)
	})
}
