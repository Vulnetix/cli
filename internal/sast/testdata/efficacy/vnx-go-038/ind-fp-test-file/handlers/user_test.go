package handlers

import (
	"encoding/json"
	"net/http"
	"testing"

	"gorm.io/gorm"
)

func TestSave(t *testing.T) {
	var db *gorm.DB
	var r *http.Request
	var u struct{ Name string }
	json.NewDecoder(r.Body).Decode(&u)
	db.Create(&u)
}
