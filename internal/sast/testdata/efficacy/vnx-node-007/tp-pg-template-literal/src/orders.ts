import { Pool } from "pg";
const pool = new Pool();

export async function ordersFor(userId: string) {
~>  const { rows } = await pool.query(`SELECT * FROM orders WHERE user_id = '${userId}'`);
  return rows;
}
