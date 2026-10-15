const db = require("./db");

async function byIds(ids) {
  return db.query(
    `SELECT * FROM tags WHERE id IN (${ids.map(() => "?").join(", ")})`,
    ids,
  );
}

async function byPg(ids) {
  return db.query(`SELECT * FROM tags WHERE id IN (${ids.map((_, i) => `$${i + 1}`).join(",")})`, ids);
}

module.exports = { byIds, byPg };
