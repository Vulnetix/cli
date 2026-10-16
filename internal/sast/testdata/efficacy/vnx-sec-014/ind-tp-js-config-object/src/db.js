const { Pool } = require('pg');

const pool = new Pool({
  host: 'db.internal',
  user: 'shop',
~>  password: 'hunter2-Prod!9',
  database: 'shop',
});

module.exports = pool;
