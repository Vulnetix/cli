def query(db, uid):
	rows = db.execute("SELECT * FROM users WHERE id = ?",
	                  (uid,)
	                  )
	return rows
