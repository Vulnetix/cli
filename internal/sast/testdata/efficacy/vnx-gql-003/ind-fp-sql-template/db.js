const sql = `SELECT * FROM users WHERE id = ${req.params.id}`;
const msg = `Hello ${req.body.name}, your query was received`;
