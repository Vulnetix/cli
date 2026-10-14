package orders

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jmoiron/sqlx"
	"gorm.io/gorm"
)

type Order struct {
	ID     int64
	Status string
	Email  string
}

func ByStatus(db *gorm.DB, status string) ([]Order, error) {
	var out []Order
~>	err := db.Raw(fmt.Sprintf("SELECT * FROM orders WHERE status = '%s'", status)).Scan(&out).Error
	return out, err
}

func ByEmail(db *gorm.DB, email string) (Order, error) {
	var o Order
~>	err := db.Where(fmt.Sprintf("email = '%s'", email)).First(&o).Error
	return o, err
}

func Matching(db *gorm.DB, q string) ([]Order, error) {
	var out []Order
~>	err := db.Model(&Order{}).Where("email LIKE '%" + q + "%'").Find(&out).Error
	return out, err
}

func ForOrg(db *sqlx.DB, org string) ([]Order, error) {
	var out []Order
~>	err := db.Select(&out, fmt.Sprintf("SELECT id, status FROM orders WHERE org = '%s'", org))
	return out, err
}

func Count(ctx context.Context, pool *pgxpool.Pool, customer string) (int, error) {
	var n int
~>	err := pool.QueryRow(ctx, "SELECT count(*) FROM orders WHERE customer_id = "+customer).Scan(&n)
	return n, err
}
