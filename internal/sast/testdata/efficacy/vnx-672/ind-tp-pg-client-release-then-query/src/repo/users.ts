import { Pool } from 'pg';

const pool = new Pool();

export async function touchUser(id: string): Promise<void> {
  const client = await pool.connect();
  await client.query('UPDATE users SET seen_at = now() WHERE id = $1', [id]);
  client.release();
~>  await client.query('INSERT INTO audit(user_id) VALUES ($1)', [id]);
}
