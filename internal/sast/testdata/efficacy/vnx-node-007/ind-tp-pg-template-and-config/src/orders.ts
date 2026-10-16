import { Pool } from 'pg';
const pool = new Pool();

export async function byUser(userId: string) {
~>  return pool.query(`SELECT * FROM orders WHERE user_id = '${userId}'`);
}

export async function byRegion(region: string) {
~>  return pool.query({ text: `SELECT * FROM sales WHERE region = '${region}'` });
}
