const mysql = require('mysql2');

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'db.acme.net',
  user: process.env.DB_USER,
  database: 'shop',
});
module.exports = pool;
