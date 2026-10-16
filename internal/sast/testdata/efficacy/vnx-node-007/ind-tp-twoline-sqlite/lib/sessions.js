const sqlite3 = require('sqlite3');
const db = new sqlite3.Database('app.db');

function revoke(token, done) {
  const sql = "DELETE FROM sessions WHERE token = '" + token + "'";
~>  db.run(sql, done);
}

module.exports = { revoke };
