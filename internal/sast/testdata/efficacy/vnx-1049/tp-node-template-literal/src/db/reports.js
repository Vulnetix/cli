const pool = require('./pool');

async function shipments(regionId) {
~>  const { rows } = await pool.query(`SELECT s.*
    FROM shipments s
    JOIN orders o ON o.id = s.order_id
    JOIN customers c ON c.id = o.customer_id
    JOIN carriers k ON k.id = s.carrier_id
    JOIN depots d ON d.id = s.depot_id
    JOIN regions r ON r.id = d.region_id
    WHERE r.id = $1`, [regionId]);
  return rows;
}

module.exports = { shipments };
