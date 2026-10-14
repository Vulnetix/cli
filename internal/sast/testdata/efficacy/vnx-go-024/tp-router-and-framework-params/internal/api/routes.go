package api

import (
	"database/sql"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/go-chi/chi/v5"
	"github.com/gofiber/fiber/v2"
	"github.com/gorilla/mux"
	"github.com/julienschmidt/httprouter"
	"github.com/labstack/echo/v4"
)

var db *sql.DB

func MuxFile(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
~>	f, err := os.Open(filepath.Join("/srv/files", name))
	if err == nil {
		f.Close()
	}
}

func ChiUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
~>	rows, err := db.Query("SELECT * FROM users WHERE id = " + id)
	if err == nil {
		rows.Close()
	}
}

func RouterNext(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	next := ps.ByName("next")
~>	http.Redirect(w, r, next, http.StatusFound)
}

func PathValueFetch(w http.ResponseWriter, r *http.Request) {
	target := r.PathValue("target")
~>	resp, err := http.Get(target)
	if err == nil {
		resp.Body.Close()
	}
}

func FiberPing(app *fiber.App) {
	app.Post("/", func(c *fiber.Ctx) error {
		endpoint := c.FormValue("endpoint")
~>		cmd := exec.Command("sh", "-c", "ping -c 2 "+endpoint)
		return cmd.Run()
	})
}

func EchoRead(c echo.Context) error {
	p := c.QueryParam("path")
~>	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	return c.Blob(http.StatusOK, "application/octet-stream", b)
}
