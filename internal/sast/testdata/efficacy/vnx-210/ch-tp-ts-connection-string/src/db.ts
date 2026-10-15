import { Pool } from 'pg';

export async function connect(connectionString: string): Promise<Pool> {
  const pool = new Pool({ connectionString });
  try {
    await pool.query('SELECT 1');
  } catch (e) {
~>    throw new Error(
      `could not reach database at ${connectionString}: ${(e as Error).message}`,
    );
  }
  return pool;
}
