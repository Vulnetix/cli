package main

import (
	"fmt"
	"net/http"
	"strconv"
)

func avg(w http.ResponseWriter, r *http.Request) {
	sum := 100
	count, err := strconv.Atoi(r.URL.Query().Get("count"))
	if err != nil {
		http.Error(w, "bad", 400)
		return
	}
~>	fmt.Fprintf(w, "%d", sum/count)
}

func shard(r *http.Request, key int) int {
	n, _ := strconv.ParseInt(r.Header.Get("X-Shards"), 10, 64)
~>	return key % int(n)
}
