export async function findUser(pool: Pool, id: string) {
  const client = await pool.connect();
  client.release();
~>  const result = await client.query('SELECT * FROM users WHERE id = $1', [id]);
  return result.rows[0];
}

export function shutdown(db) {
  db.close();
~>  db.run('DELETE FROM sessions');
}
