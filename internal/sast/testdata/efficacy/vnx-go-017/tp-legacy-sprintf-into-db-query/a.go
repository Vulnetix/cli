package a

func f(db *sql.DB, name string) {
~>	db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name))
}
