package web

import (
	"fmt"
	"net/http"

	"gorm.io/gorm"
)

func Search(db *gorm.DB, r *http.Request) {
	var rows []map[string]any
~>	db.Raw(fmt.Sprintf("SELECT * FROM items WHERE title LIKE '%%%s%%'", r.URL.Query().Get("q"))).Scan(&rows)
}
