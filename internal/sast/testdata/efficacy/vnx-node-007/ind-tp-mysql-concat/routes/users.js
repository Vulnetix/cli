const mysql = require('mysql2');
const connection = mysql.createConnection(process.env.DATABASE_URL);

exports.show = (req, res) => {
~>  connection.query("SELECT * FROM users WHERE id = " + req.params.id, (err, rows) => {
    if (err) return res.status(500).end();
    res.json(rows);
  });
};
