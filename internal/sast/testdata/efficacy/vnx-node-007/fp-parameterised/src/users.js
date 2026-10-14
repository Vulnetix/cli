const pool = require('./pool');
const connection = require('./mysql');

async function find(id, email) {
  await pool.query('SELECT * FROM users WHERE id = $1', [id]);
  connection.query("SELECT * FROM users WHERE email = ?", [email], () => {});
  await pool.query(`SELECT count(*) FROM users`);
  return pool.query({ text: 'UPDATE users SET seen = now() WHERE id = $1', values: [id] });
}
module.exports = find;
