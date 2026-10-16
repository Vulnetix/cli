package main

import (
	"net/http"
	"plugin"
)

func load(w http.ResponseWriter, r *http.Request) {
	p, _ := plugin.Open(r.FormValue("plugin"))
	_ = p
}
