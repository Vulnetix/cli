const { Pool } = require("pg");
const pool = new Pool();

async function byRegion(region, sort) {
~>  const { rows } = await pool.query({ text: `SELECT * FROM sales WHERE region = '${region}'` });
  const sorted = await pool.query({
    text: "SELECT * FROM sales WHERE region = $1 ORDER BY total",
    values: [region],
  });
  return { rows, sorted, sort };
}

module.exports = { byRegion };
