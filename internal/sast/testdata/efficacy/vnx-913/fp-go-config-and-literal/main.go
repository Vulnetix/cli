package main

import (
	"net/http"
	"os"
	"syscall"

	lua "github.com/yuin/gopher-lua"
)

func boot(w http.ResponseWriter, r *http.Request) {
	L := lua.NewState()
	_ = r.FormValue("ignored")
	_ = L.DoFile("/etc/app/init.lua")
	_ = L.DoFile(os.Getenv("APP_INIT"))
	d, _ := syscall.LoadDLL("kernel32.dll")
	_ = d
}
