package api

import (
	"net/http"
	"strconv"
)

type Page struct {
	Limit int32
	Port  uint16
}

// ?limit=4294967297 becomes Limit 1; ?port=65616 becomes port 80.
func ParsePage(r *http.Request) (Page, error) {
	n, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil {
		return Page{}, err
	}
	p, err := strconv.Atoi(r.URL.Query().Get("port"))
	if err != nil {
		return Page{}, err
	}
	return Page{
~>		Limit: int32(n),
~>		Port:  uint16( p ),
	}, nil
}

func Shard(s string) byte {
	id, _ := strconv.Atoi(s)
~>	return byte(id)
}
