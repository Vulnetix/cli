const db = require('./pool');

async function find(req) {
  const name = req.query.name;
  const filter = { name: req.body.name };
  const query = `SELECT * FROM users WHERE name = $1`;
  const label = `query took ${Date.now()} ms for ${name.length} chars`;
  function query2(x) { return x; }
  return [await db.query(query, [name]), filter, label, query2];
}

module.exports = { find };
