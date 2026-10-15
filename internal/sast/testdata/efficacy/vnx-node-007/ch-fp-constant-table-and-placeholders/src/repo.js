const TABLE = "accounts";
const COLUMNS = "id, email, created_at";

async function byId(pool, id) {
  return pool.query(`SELECT ${COLUMNS} FROM ${TABLE} WHERE id = $1`, [id]);
}

async function byIds(pool, ids) {
  const marks = ids.map((_, i) => `$${i + 1}`).join(", ");
  return pool.query(`SELECT * FROM ${TABLE} WHERE id IN (${marks})`, ids);
}

module.exports = { byId, byIds };
