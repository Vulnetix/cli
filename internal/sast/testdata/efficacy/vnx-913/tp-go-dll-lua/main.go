package main

import (
	"net/http"

	lua "github.com/yuin/gopher-lua"
	"golang.org/x/sys/windows"
)

func driver(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("driver")
~>	dll, err := windows.LoadDLL(name + ".dll")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	_ = dll
}

func script(w http.ResponseWriter, r *http.Request) {
	L := lua.NewState()
	defer L.Close()
	f := r.FormValue("script")
~>	if err := L.DoFile(f); err != nil {
		http.Error(w, err.Error(), 500)
	}
}
