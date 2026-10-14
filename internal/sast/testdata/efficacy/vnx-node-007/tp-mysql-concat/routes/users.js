const mysql = require('mysql');
const connection = mysql.createConnection({ host: 'db' });

exports.show = (req, res) => {
~>  connection.query("SELECT * FROM users WHERE id = " + req.params.id, (err, rows) => {
    res.json(rows);
  });
};
