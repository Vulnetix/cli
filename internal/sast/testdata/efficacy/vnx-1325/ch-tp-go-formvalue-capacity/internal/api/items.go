package api

import (
	"net/http"
	"strconv"
)

func listItems(w http.ResponseWriter, r *http.Request) {
	count, err := strconv.Atoi(r.FormValue("count"))
	if err != nil || count < 0 {
		http.Error(w, "bad count", http.StatusBadRequest)
		return
	}
~>	items := make([]Item, 0, count)
	for _, it := range store.All() {
		items = append(items, it)
	}
	writeJSON(w, items)
}
