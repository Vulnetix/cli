const Database = require('better-sqlite3');

const db = new Database('app.db');
const ID_RE = /^(\d+)-([a-z]+)$/;

function parse(req, res) {
  const m = ID_RE.exec(req.query.id);
  const n = /(\d+)/.exec(req.body.text);
  db.exec('CREATE TABLE IF NOT EXISTS t (id INTEGER)');
  const rows = db.prepare('SELECT * FROM t WHERE id = ?').all(req.params.id);
  res.json({ m, n, rows });
}

module.exports = { parse };
