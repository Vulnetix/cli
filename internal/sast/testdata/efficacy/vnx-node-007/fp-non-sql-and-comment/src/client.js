// Bad: db.query("SELECT * FROM t WHERE id = " + id)
const doc = "pool.query(`SELECT * FROM t WHERE id = ${id}`) is unsafe";
async function load(api, id) {
  const res = await api.get(`/users/${id}`);
  const q = url.query(`page=${id}`);
  return [res, q, doc];
}
module.exports = load;
