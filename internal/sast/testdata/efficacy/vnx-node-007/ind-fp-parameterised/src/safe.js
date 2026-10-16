const { sql } = require('slonik');

async function run(connection, pool, knex, prisma, req) {
  const [rows] = await connection.execute('SELECT * FROM users WHERE id = ?', [req.params.id]);
  const r = await pool.query('SELECT * FROM products WHERE name = $1', [req.query.name]);
  const k = await knex('users').where('id', req.params.id);
  const p = await prisma.$queryRaw`SELECT * FROM "User" WHERE id = ${req.params.id}`;
  const s = await pool.query(sql`SELECT * FROM t WHERE a = ${req.query.a}`);
  const all = await pool.query('SELECT count(*) FROM audit');
  return { rows, r, k, p, s, all };
}

module.exports = { run };
