package a

func f(db *sql.DB, id string) {
~>	db.Exec("DELETE FROM users WHERE id = " + id)
~>	q := "SELECT * FROM t WHERE name = '" + name + "'"
}
