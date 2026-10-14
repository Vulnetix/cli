package a

func f(db *sql.DB, n int) {
	db.Query(fmt.Sprintf("SELECT * FROM users LIMIT %d", n))
}
