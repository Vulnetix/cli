package handlers

import (
	"net/http"

	"github.com/beego/beego/v2/server/web"
	"github.com/gofiber/fiber/v3"
	"github.com/gorilla/mux"
	"github.com/julienschmidt/httprouter"
)

func Go(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
~>	http.Redirect(w, r, vars["target"], http.StatusFound)
}

func Visit(w http.ResponseWriter, r *http.Request) {
	dest := r.PathValue("dest")
~>	redirectTo(w, r, dest)
}

func Follow(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	to := ps.ByName("to")
~>	http.Redirect(w, r, to, http.StatusTemporaryRedirect)
}

func Next(c fiber.Ctx) error {
	target := c.Query("next")
~>	return c.Redirect().To(target)
}

type LinkController struct{ web.Controller }

func (this *LinkController) Get() {
	u := this.GetString("u")
~>	this.Redirect(u, http.StatusFound)
}

func redirectTo(w http.ResponseWriter, r *http.Request, u string) {
	http.Redirect(w, r, u, http.StatusFound)
}
