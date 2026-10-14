package store

import (
	"fmt"

	"github.com/jmoiron/sqlx"
	"gorm.io/gorm"
)

type Product struct {
	ID   int
	Name string
}

func Search(db *sqlx.DB, term string) ([]Product, error) {
	var out []Product
~>	err := db.Select(&out, fmt.Sprintf("SELECT id, name FROM products WHERE name LIKE '%%%s%%'", term))
	return out, err
}

func SetRole(db *sqlx.DB, id int, role string) {
~>	db.MustExec(fmt.Sprintf("UPDATE accounts SET role = '%v' WHERE id = %d", role, id))
}

func ByOwner(g *gorm.DB, owner string) []Product {
	var out []Product
~>	g.Raw(fmt.Sprintf(`SELECT * FROM products WHERE owner = "%s"`, owner)).Scan(&out)
	return out
}

func Insert(db *sqlx.DB, name, sku string) error {
~>	_, err := db.Exec(fmt.Sprintf("INSERT INTO products (name, sku) VALUES ('%s', '%s')", name, sku))
	return err
}
