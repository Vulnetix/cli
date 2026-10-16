package repo

import (
	"fmt"

	"gorm.io/gorm"
)

type Product struct {
	ID       uint
	Category string
}

func ByCategory(db *gorm.DB, category string) ([]Product, error) {
	var out []Product
~>	err := db.Raw(fmt.Sprintf("SELECT * FROM products WHERE category = '%s'", category)).Scan(&out).Error
	return out, err
}
