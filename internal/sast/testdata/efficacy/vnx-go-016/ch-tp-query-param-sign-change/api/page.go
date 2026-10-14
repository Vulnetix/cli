package api

import (
	"net/http"
	"strconv"
)

func Page(w http.ResponseWriter, r *http.Request) {
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil {
		http.Error(w, "bad limit", http.StatusBadRequest)
		return
	}
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
~>	rows := fetch(uint32(offset),
~>		uint32(limit))
	_ = rows
}

func Slot(s string) uint8 {
	v, _ := strconv.ParseUint(s, 10, 32)
~>	return uint8(v)
}

func Idx(s string) int32 {
	u, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return -1
	}
~>	return int32(u)
}

func fetch(off, lim uint32) []string { return nil }
