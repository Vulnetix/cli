const pool = require("../pool");

module.exports = async function report(req, res) {
  let sql = "SELECT * FROM sales WHERE region = '" + req.query.region + "'";
  sql += " AND year = " + req.query.year;
~>  const { rows } = await pool.query(sql);
  res.json(rows);
};
