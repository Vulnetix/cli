import { pool } from "../db";

export async function revenueByRegion(year: number) {
~>  const sql = `WITH paid AS (SELECT order_id, amount FROM payments WHERE status = 'paid')
    SELECT r.name, SUM(p.amount)
    FROM orders o
    JOIN paid p ON p.order_id = o.id
    JOIN customers c ON c.id = o.customer_id
    LEFT JOIN addresses a ON a.id = c.billing_address_id
    LEFT JOIN regions r ON r.id = a.region_id
    WHERE EXTRACT(YEAR FROM o.created_at) = $1
    GROUP BY r.name`;
  const res = await pool.query(sql, [year]);
  return res.rows;
}
