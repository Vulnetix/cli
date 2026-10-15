const db = require('./db');

async function find(req, res) {
  const name = req.query.name;
  const greeting = `Hello { ${name} }, your query is being processed`;
  const rows = await db.query('SELECT * FROM users WHERE name = $1', [name]);
  res.json({ greeting, rows });
}

module.exports = { find };
