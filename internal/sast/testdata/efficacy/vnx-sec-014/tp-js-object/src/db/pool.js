const { Pool } = require('pg');

const pool = new Pool({
  host: 'db.internal',
  user: 'reporting',
~>  password: 'r3p0rt!ng-Pr0d',
  database: 'analytics',
});

~>let adminPassword = "S3cureAdm1n#";
module.exports = { pool, adminPassword };
