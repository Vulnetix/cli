const mysql = require('mysql2');

async function report(pool, req, ids) {
  const limit = Number(req.query.limit);
  const a = await pool.query(`SELECT * FROM events ORDER BY ts DESC LIMIT ${limit}`);
  const page = parseInt(req.query.page, 10);
  const b = await pool.query(`SELECT * FROM events LIMIT 20 OFFSET ${page * 20}`);
  const c = await pool.query(`SELECT * FROM users WHERE name = ${mysql.escape(req.query.name)}`);
  const d = await pool.query(`SELECT * FROM ${mysql.escapeId(req.query.table)}`);
  const e = await pool.query(`SELECT * FROM users WHERE id IN (${ids.map(() => "?").join(",")})`, ids);
  return [a, b, c, d, e];
}

module.exports = { report };
