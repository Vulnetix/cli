const { Pool } = require("pg");

~>const pool = new Pool({ connectionString: `postgres://svc:@@sample:[A-Za-z0-9]{20}@@@pg.acme.internal:5432/app` });
module.exports = pool;
