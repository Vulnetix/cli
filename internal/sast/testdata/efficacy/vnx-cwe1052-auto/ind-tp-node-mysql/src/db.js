const mysql = require('mysql2');

const pool = mysql.createPool({
~>  host: '172.16.8.40',
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: 'shop',
});
module.exports = pool;
