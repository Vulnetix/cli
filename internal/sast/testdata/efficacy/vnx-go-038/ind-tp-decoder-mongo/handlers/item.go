package handlers

import (
	"encoding/json"
	"net/http"

	"go.mongodb.org/mongo-driver/mongo"
)

type Item struct {
	Name  string `json:"name"`
	Owner string `json:"owner"`
}

func AddItem(coll *mongo.Collection) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var it Item
~>		if err := json.NewDecoder(r.Body).Decode(&it); err != nil {
			http.Error(w, "bad", 400)
			return
		}
		_, err := coll.InsertOne(r.Context(), it)
		if err != nil {
			http.Error(w, "db", 500)
		}
	}
}
