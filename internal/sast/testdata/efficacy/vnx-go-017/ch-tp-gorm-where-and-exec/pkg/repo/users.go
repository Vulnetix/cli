package repo

import (
	"fmt"

	"gorm.io/gorm"
)

type User struct {
	ID   uint
	Name string
}

func FindByName(db *gorm.DB, name string) (User, error) {
	var u User
~>	err := db.Where(fmt.Sprintf("name = '%s'", name)).First(&u).Error
	return u, err
}

func Search(db *gorm.DB, term string) ([]User, error) {
	var out []User
~>	q := fmt.Sprintf("SELECT * FROM users WHERE name LIKE '%%%s%%'", term)
	err := db.Raw(q).Scan(&out).Error
	return out, err
}
