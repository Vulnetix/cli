import { Pool } from 'pg';

export async function find(pool: Pool, id: number) {
  const client = await pool.connect();
  const first = await client.query('select 1');
  client.release();
~>  const res = await client.query('select * from users where id = $1', [id]);
  return res.rows;
}
