async function insertMany(pool, rows) {
  const values = rows.map((_, i) => `($${i * 2 + 1}, $${i * 2 + 2})`).join(', ');
  return pool.query(`INSERT INTO tags (name, color) VALUES ${values}`, rows.flat());
}
module.exports = insertMany;
