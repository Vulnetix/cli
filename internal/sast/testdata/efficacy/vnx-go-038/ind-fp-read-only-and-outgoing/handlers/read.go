package handlers

import (
	"encoding/json"
	"net/http"

	"gorm.io/gorm"
)

type Query struct{ Term string }
type Remote struct{ Name string }

func Search(db *gorm.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var q Query
		json.NewDecoder(r.Body).Decode(&q)
		var out []Remote
		db.Where("name LIKE ?", q.Term).Find(&out)
		json.NewEncoder(w).Encode(out)
	}
}

func Fetch(db *gorm.DB) {
	resp, _ := http.Get("https://api.example.com/x")
	var rm Remote
	json.NewDecoder(resp.Body).Decode(&rm)
	db.Create(&rm)
}
